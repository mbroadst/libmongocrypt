/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bson/bson.h>

#include "mongocrypt.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-key-broker-private.h"

typedef enum {
   _MONGOCRYPT_TYPE_NONE,
   _MONGOCRYPT_TYPE_ENCRYPT,
   _MONGOCRYPT_TYPE_DECRYPT,
} _mongocrypt_ctx_type_t;


typedef bool (*_mongocrypt_ctx_mongo_op_fn) (mongocrypt_ctx_t *ctx,
                                              mongocrypt_binary_t *out);

typedef bool (*_mongocrypt_ctx_mongo_feed_fn) (mongocrypt_ctx_t *ctx,
                                                mongocrypt_binary_t *in);

typedef bool (*_mongocrypt_ctx_mongo_done_fn) (mongocrypt_ctx_t *ctx);

typedef bool (*_mongocrypt_ctx_finalize_fn) (mongocrypt_ctx_t *ctx,
                                             mongocrypt_binary_t *out);


typedef struct {
   _mongocrypt_ctx_mongo_op_fn mongo_op_collinfo;
   _mongocrypt_ctx_mongo_feed_fn mongo_feed_collinfo;
   _mongocrypt_ctx_mongo_done_fn mongo_done_collinfo;
   
   _mongocrypt_ctx_mongo_op_fn mongo_op_markings;
   _mongocrypt_ctx_mongo_feed_fn mongo_feed_markings;
   _mongocrypt_ctx_mongo_done_fn mongo_done_markings;

   _mongocrypt_ctx_finalize_fn finalize;
} _mongocrypt_vtable_t;


struct _mongocrypt_ctx_t {
   mongocrypt_t *crypt;
   mongocrypt_ctx_state_t state;
   _mongocrypt_ctx_type_t type;
   mongocrypt_status_t *status;
   mongocrypt_key_broker_t kb;
   _mongocrypt_vtable_t vtable;
};


typedef struct {
   struct _mongocrypt_ctx_t parent;
   const char *ns;
   _mongocrypt_buffer_t list_collections_filter;
   _mongocrypt_buffer_t schema;
   _mongocrypt_buffer_t original_cmd;
   _mongocrypt_buffer_t marking_cmd;
   _mongocrypt_buffer_t marked_cmd;
   _mongocrypt_buffer_t encrypted_cmd;
} _mongocrypt_ctx_encrypt_t;


typedef struct {
   struct _mongocrypt_ctx_t parent;
} _mongocrypt_ctx_decrypt_t;


mongocrypt_ctx_t *
mongocrypt_ctx_new (mongocrypt_t *crypt)
{
   mongocrypt_ctx_t *ctx;
   int ctx_size;

   ctx_size = sizeof (_mongocrypt_ctx_encrypt_t);
   if (sizeof (_mongocrypt_ctx_decrypt_t) > ctx_size) {
      ctx_size = sizeof (_mongocrypt_ctx_decrypt_t);
   }
   ctx = bson_malloc0 (ctx_size);
   ctx->crypt = crypt;
   _mongocrypt_key_broker_init (&ctx->kb);
   ctx->status = mongocrypt_status_new ();
   return ctx;
}


/* Construct the list collections command to send. */
bool
_mongocrypt_ctx_mongo_op_collinfo_encrypt (mongocrypt_ctx_t *ctx,
                                mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *cmd;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   cmd = BCON_NEW ("name",
                   BCON_UTF8 (ectx->ns),
                   "options.validator.$jsonSchema",
                   "{",
                   "$exists",
                   BCON_BOOL (true),
                   "}");
   CRYPT_TRACEF (&ectx->parent.crypt->log, "constructed: %s\n", tmp_json (cmd));
   _mongocrypt_buffer_steal_from_bson (&ectx->list_collections_filter, cmd);
   out->data = ectx->list_collections_filter.data;
   out->len = ectx->list_collections_filter.len;
   return true;
}


bool
_mongocrypt_ctx_mongo_feed_collinfo_encrypt (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *in)
{
   /* Parse out the schema. */
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   BSON_ASSERT (bson_init_static (&as_bson, in->data, in->len));
   bson_iter_init (&iter, &as_bson);
   if (bson_iter_find_descendant (&iter, "options.validator.$jsonSchema", &iter)) {
      _mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter);
   }
   return true;
}


bool
_mongocrypt_ctx_mongo_done_collinfo_encrypt (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   if (_mongocrypt_buffer_empty (&ectx->schema)) {
      ectx->parent.state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else {
      ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   }
   return true;
}


bool
_mongocrypt_ctx_mongo_op_markings_encrypt (mongocrypt_ctx_t *ctx,
                                  mongocrypt_binary_t *out)
{
   /* Append the schema to the command. */
   bson_t as_bson, marking_cmd, schema;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   _mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson);
   bson_copy_to (&as_bson, &marking_cmd);
   _mongocrypt_buffer_to_bson (&ectx->schema, &schema);
   bson_append_document (&marking_cmd, "jsonSchema", -1, &schema);
   _mongocrypt_buffer_steal_from_bson (&ectx->marking_cmd, &marking_cmd);
   out->data = ectx->marking_cmd.data;
   out->len = ectx->marking_cmd.len;
   return true;
}


static bool
_collect_key_from_marking (void *ctx, _mongocrypt_buffer_t *in)
{
   mongocrypt_status_t *status;
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   status = ectx->parent.status;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   /* TODO: check if the key cache has the key. */
   /* TODO: support keyAltName. */
   if (marking.key_alt_name) {
      CLIENT_ERR ("keyAltName not supported yet");
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (&ectx->parent.kb, &marking.key_id)) {
      mongocrypt_status_copy_to (ectx->parent.kb.status, ectx->parent.status);
      return false;
   }
   return true;
}


bool
_mongocrypt_ctx_mongo_feed_markings_encrypt (mongocrypt_ctx_t *ctx,
                                        mongocrypt_binary_t *in)
{
   /* Find keys. */
   mongocrypt_status_t *status;
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   status = ectx->parent.status;
   _mongocrypt_binary_to_bson (in, &as_bson);

   if (!bson_iter_init_find (&iter, &as_bson, "result")) {
      CLIENT_ERR ("marked reply does not have 'result'");
      ectx->parent.state = MONGOCRYPT_CTX_ERROR;
      return false;
   }

   _mongocrypt_buffer_copy_from_document_iter (&ectx->marked_cmd, &iter);

   bson_iter_recurse (&iter, &iter);
   if (!_mongocrypt_traverse_binary_in_bson (
          _collect_key_from_marking, (void *) ectx, 0, &iter, status)) {
      /* TODO: rebase on recent fixes for the first byte. */
      ectx->parent.state = MONGOCRYPT_CTX_ERROR;
      return false;
   }

   return false;
}


bool
_mongocrypt_ctx_mongo_done_markings_encrypt (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t*)ctx;
   if (_mongocrypt_key_broker_empty (&ectx->parent.kb)) {
      /* if there were no keys, i.e. no markings, no encryption is needed. */
      ectx->parent.state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else {
      ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   }
   return true;
}


/* Common to both encrypt and decrypt context. */
bool
_mongocrypt_ctx_mongo_op_keys (mongocrypt_ctx_t *ctx,
                          mongocrypt_binary_t *out)
{
   /* Construct the find filter to fetch keys. */
   bson_t filter;

   _mongocrypt_key_broker_filter (&ctx->kb, &filter);
   out->data = bson_destroy_with_steal (&filter, true, &out->len);
   return true;
}


bool
_mongocrypt_ctx_mongo_feed_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_buffer_t buf;

   _mongocrypt_buffer_from_binary (&buf, in);
   _mongocrypt_key_broker_add_doc (&ctx->kb, &buf);

   /* TODO: currently this just takes the first key. Fix this to handle multiple
    * keys. */
   mongocrypt_key_broker_done_adding_keys (&ctx->kb);
   return true;
}


bool
_mongocrypt_ctx_mongo_done_keys (mongocrypt_ctx_t *ctx) {
   /* TODO: fail the ctx. Make a generic fail_w_status. */
   ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   return mongocrypt_key_broker_done_adding_keys (&ctx->kb);
}


bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx,
                          mongocrypt_binary_t *out)
{
   mongocrypt_status_t *status;

   status = ctx->status;
   switch (ctx->state) {
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return ctx->vtable.mongo_op_collinfo (ctx, out);
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return ctx->vtable.mongo_op_markings (ctx, out);
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return _mongocrypt_ctx_mongo_op_keys (ctx, out);
      case MONGOCRYPT_CTX_NEED_KMS:
      case MONGOCRYPT_CTX_ERROR:
      case MONGOCRYPT_CTX_DONE:
      case MONGOCRYPT_CTX_READY:
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
      CLIENT_ERR ("wrong state");
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
}


bool
mongocrypt_ctx_mongo_feed (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   mongocrypt_status_t* status;

   status = ctx->status;
   switch (ctx->state) {
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return ctx->vtable.mongo_feed_collinfo (ctx, in);
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return ctx->vtable.mongo_feed_markings (ctx, in);
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return _mongocrypt_ctx_mongo_feed_keys (ctx, in);
      case MONGOCRYPT_CTX_NEED_KMS:
      case MONGOCRYPT_CTX_ERROR:
      case MONGOCRYPT_CTX_DONE:
      case MONGOCRYPT_CTX_READY:
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
      CLIENT_ERR ("wrong state");
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
}


bool
mongocrypt_ctx_mongo_done (mongocrypt_ctx_t *ctx)
{
   mongocrypt_status_t* status;

   status = ctx->status;
   switch (ctx->state) {
      case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return ctx->vtable.mongo_done_collinfo (ctx);
      case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return ctx->vtable.mongo_done_markings (ctx);
      case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return _mongocrypt_ctx_mongo_done_keys (ctx);
      case MONGOCRYPT_CTX_NEED_KMS:
      case MONGOCRYPT_CTX_ERROR:
      case MONGOCRYPT_CTX_DONE:
      case MONGOCRYPT_CTX_READY:
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
      CLIENT_ERR ("wrong state");
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
}


mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx)
{
   return ctx->state;
}


mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *msg)
{
   mongocrypt_key_decryptor_t *kd;
   mongocrypt_binary_t *tmp;

   kd = mongocrypt_key_broker_next_decryptor (&ctx->kb);
   tmp = mongocrypt_key_decryptor_msg (kd);
   msg->data = tmp->data;
   msg->len = tmp->len;
   mongocrypt_binary_destroy (tmp);
   return (mongocrypt_kms_ctx_t *) kd;
}


bool
mongocrypt_kms_ctx_feed (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *data)
{
   mongocrypt_key_decryptor_t *kd;

   kd = (mongocrypt_key_decryptor_t *) kms;
   return mongocrypt_key_decryptor_feed (kd, data);
}


uint32_t
mongocrypt_kms_ctx_bytes_needed (mongocrypt_kms_ctx_t *kms)
{
   return mongocrypt_key_decryptor_bytes_needed (
      (mongocrypt_key_decryptor_t *) kms, 1024);
}


bool
mongocrypt_ctx_kms_ctx_done (mongocrypt_ctx_t *ctx, mongocrypt_kms_ctx_t *kms)
{
   /* TODO: check if this is the last remaining open kms request */
   ctx->state = MONGOCRYPT_CTX_READY;
   _mongocrypt_key_broker_add_decrypted_key (
      &ctx->kb, (mongocrypt_key_decryptor_t *) kms);
   return true;
}


/* From BSON Binary subtype 6 specification:
struct fle_blob {
 uint8  fle_blob_subtype = (1 or 2);
 uint8  key_uuid[16];
 uint8  original_bson_type;
 uint8  ciphertext[ciphertext_length];
}
TODO CDRIVER-3001 this may not be the right home for this method.
*/
static void
_serialize_ciphertext (_mongocrypt_ciphertext_t *ciphertext,
                       _mongocrypt_buffer_t *out)
{
   uint32_t offset;

   BSON_ASSERT (ciphertext);
   BSON_ASSERT (out);
   BSON_ASSERT (ciphertext->key_id.len == 16);

   /* TODO CDRIVER-3001: relocate this logic? */
   offset = 0;
   out->len = 1 + ciphertext->key_id.len + 1 + ciphertext->data.len;
   out->data = bson_malloc0 (out->len);

   out->data[offset] = ciphertext->blob_subtype;
   offset += 1;

   memcpy (out->data + offset, ciphertext->key_id.data, ciphertext->key_id.len);
   offset += ciphertext->key_id.len;

   out->data[offset] = ciphertext->original_bson_type;
   offset += 1;

   memcpy (out->data + offset, ciphertext->data.data, ciphertext->data.len);
   offset += ciphertext->data.len;
}


static bool
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out)
{
   mongocrypt_status_t *status;
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {0};
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   _mongocrypt_buffer_t plaintext = {0};
   mongocrypt_key_broker_t *kb;
   bson_t wrapper = BSON_INITIALIZER;
   const _mongocrypt_buffer_t *key_material;
   bool ret = false;
   uint32_t bytes_written;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   kb = (mongocrypt_key_broker_t *) ctx;
   status = kb->status;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      goto fail;
   }

   if (marking.key_alt_name) {
      CLIENT_ERR ("TODO looking up key by keyAltName not yet supported");
      goto fail;
   }

   ciphertext.blob_subtype = marking.algorithm;
   ciphertext.original_bson_type = (uint8_t) bson_iter_type (&marking.v_iter);

   /* get the key for this marking. */
   key_material =
      _mongocrypt_key_broker_decrypted_key_material_by_id (kb, &marking.key_id);
   if (!key_material) {
      mongocrypt_status_copy_to (kb->status, status);
      goto fail;
   }

   /* TODO: for simplicity, we wrap the thing we encrypt in a BSON document
    * with an empty key, i.e. { "": <thing to encrypt> }
    * CDRIVER-3021 will remove this. */
   bson_append_iter (&wrapper, "", 0, &marking.v_iter);
   plaintext.data = (uint8_t *) bson_get_data (&wrapper);
   plaintext.len = wrapper.len;

   ciphertext.data.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext.data.data = bson_malloc (ciphertext.data.len);
   ciphertext.data.owned = true;
   ret = _mongocrypt_do_encryption (&marking.iv,
                                    NULL,
                                    key_material,
                                    &plaintext,
                                    &ciphertext.data,
                                    &bytes_written,
                                    status);
   if (!ret) {
      goto fail;
   }
   BSON_ASSERT (bytes_written == ciphertext.data.len);

   memcpy (&ciphertext.key_id, &marking.key_id, sizeof (_mongocrypt_buffer_t));
   _serialize_ciphertext (&ciphertext, &serialized_ciphertext);

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

   ret = true;

fail:
   bson_free (ciphertext.data.data);
   bson_destroy (&wrapper);
   return ret;
}


bool
_mongocrypt_ctx_encrypt_finalize (mongocrypt_ctx_t *ctx,
                                  mongocrypt_binary_t *out)
{
   bson_t as_bson, converted;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;
   mongocrypt_status_t *status;

   status = ctx->status;
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   _mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson);
   bson_iter_init (&iter, &as_bson);
   bson_init (&converted);
   if (!_mongocrypt_transform_binary_in_bson (_replace_marking_with_ciphertext,
                                              &ctx->kb,
                                              0,
                                              &iter,
                                              &converted,
                                              status)) {
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
   out->data = bson_destroy_with_steal (&converted, true, &out->len);
   ctx->state = MONGOCRYPT_CTX_DONE;
   return true;
}


bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   return ctx->vtable.finalize (ctx, out);
}


bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             uint32_t ns_len,
                             mongocrypt_binary_t *cmd)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->ns = bson_strdup (ns);
   /* TODO: check if schema is cached. If we know encryption isn't needed. We
    * can avoid a needless copy. */
   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, cmd);
   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   ctx->vtable.mongo_op_collinfo = _mongocrypt_ctx_mongo_op_collinfo_encrypt;
   ctx->vtable.mongo_feed_collinfo = _mongocrypt_ctx_mongo_feed_collinfo_encrypt;
   ctx->vtable.mongo_done_collinfo = _mongocrypt_ctx_mongo_done_collinfo_encrypt;
   ctx->vtable.mongo_op_markings = _mongocrypt_ctx_mongo_op_markings_encrypt;
   ctx->vtable.mongo_feed_markings = _mongocrypt_ctx_mongo_feed_markings_encrypt;
   ctx->vtable.mongo_done_markings = _mongocrypt_ctx_mongo_done_markings_encrypt;
   ctx->vtable.finalize = _mongocrypt_ctx_encrypt_finalize;
   return true;
}


bool
mongocrypt_ctx_status (mongocrypt_ctx_t *ctx, mongocrypt_status_t *out)
{
   if (!mongocrypt_status_ok (ctx->status)) {
      mongocrypt_status_copy_to (ctx->status, out);
      return false;
   }
   mongocrypt_status_reset (out);
   return true;
}


void
mongocrypt_ctx_destroy (mongocrypt_ctx_t *ctx)
{
   return;
}
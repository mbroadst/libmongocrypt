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


#define FAIL_CTX(...)                                        \
   do {                                                      \
      _mongocrypt_set_error (ctx->status,                    \
                             MONGOCRYPT_STATUS_ERROR_CLIENT, \
                             MONGOCRYPT_GENERIC_ERROR_CODE,  \
                             __VA_ARGS__);                   \
      ctx->state = MONGOCRYPT_CTX_ERROR;                     \
   } while (0);


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
   _mongocrypt_buffer_t original_doc;
   _mongocrypt_buffer_t decrypted_doc;
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
   _mongocrypt_key_broker_init (&ctx->kb, true); /* TODO: do this in sub contexts. */
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

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
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

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   BSON_ASSERT (bson_init_static (&as_bson, in->data, in->len));
   bson_iter_init (&iter, &as_bson);
   if (bson_iter_find_descendant (
          &iter, "options.validator.$jsonSchema", &iter)) {
      _mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter);
   }
   return true;
}


bool
_mongocrypt_ctx_mongo_done_collinfo_encrypt (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
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
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   out->data = ectx->schema.data;
   out->len = ectx->schema.len;
   return true;
}


static bool
_collect_key_from_marking (void *ctx, _mongocrypt_buffer_t *in, mongocrypt_status_t* status)
{
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

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
      mongocrypt_status_copy_to (ectx->parent.kb.status, status);
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

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   status = ectx->parent.status;
   _mongocrypt_binary_to_bson (in, &as_bson);

   if (!bson_iter_init_find (&iter, &as_bson, "result")) {
      CLIENT_ERR ("marked reply does not have 'result'");
      ectx->parent.state = MONGOCRYPT_CTX_ERROR;
      return false;
   }

   _mongocrypt_buffer_copy_from_document_iter (&ectx->marked_cmd, &iter);

   bson_iter_recurse (&iter, &iter);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_marking,
                                             (void *) ectx,
                                             TRAVERSE_MATCH_MARKING,
                                             &iter,
                                             status)) {
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

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
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
_mongocrypt_ctx_mongo_op_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   /* Construct the find filter to fetch keys. */
   return _mongocrypt_key_broker_filter (&ctx->kb, out);
}


bool
_mongocrypt_ctx_mongo_feed_keys (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   _mongocrypt_buffer_t buf;

   _mongocrypt_buffer_from_binary (&buf, in);
   _mongocrypt_key_broker_add_doc (&ctx->kb, &buf);

   return true;
}


bool
_mongocrypt_ctx_mongo_done_keys (mongocrypt_ctx_t *ctx)
{
   /* TODO: fail the ctx. Make a generic fail_w_status. */
   ctx->state = MONGOCRYPT_CTX_NEED_KMS;
   return _mongocrypt_key_broker_done_adding_docs (&ctx->kb);
}


bool
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
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
   mongocrypt_status_t *status;

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
   mongocrypt_status_t *status;

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
   mongocrypt_kms_ctx_t *kms;

   kms = _mongocrypt_key_broker_next_kms (&ctx->kb);
   if (!kms) {
      return NULL;
   }
   /* TODO: don't reach into kms struct? */
   msg->data = kms->msg.data;
   msg->len = kms->msg.len;
   return (mongocrypt_kms_ctx_t *) kms;
}


bool
mongocrypt_ctx_kms_done (mongocrypt_ctx_t *ctx)
{
   if (!_mongocrypt_key_broker_kms_done (&ctx->kb)) {
      _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
   ctx->state = MONGOCRYPT_CTX_READY;
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
                                  bson_value_t *out,
                                  mongocrypt_status_t* status)
{
   _mongocrypt_marking_t marking = {0};
   _mongocrypt_ciphertext_t ciphertext = {{0}};
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   _mongocrypt_buffer_t plaintext = {0};
   mongocrypt_key_broker_t *kb;
   bson_t wrapper = BSON_INITIALIZER;
   _mongocrypt_buffer_t key_material;
   bool ret = false;
   uint32_t bytes_written;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);
   kb = (mongocrypt_key_broker_t *) ctx;

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
   if (!_mongocrypt_key_broker_decrypted_key_material_by_id (kb, &marking.key_id, &key_material)) {
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
                                    &key_material,
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
                                              TRAVERSE_MATCH_MARKING,
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


static bool
_mongocrypt_ctx_mongo_op_invalid (mongocrypt_ctx_t *ctx,
                                  mongocrypt_binary_t *out)
{
   FAIL_CTX ("invalid state");
   return false;
}


static bool
_mongocrypt_ctx_mongo_feed_invalid (mongocrypt_ctx_t *ctx,
                                    mongocrypt_binary_t *in)
{
   FAIL_CTX ("invalid state");
   return false;
}


static bool
_mongocrypt_ctx_mongo_done_invalid (mongocrypt_ctx_t *ctx)
{
   FAIL_CTX ("invalid state");
   return false;
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


bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             uint32_t ns_len)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->ns = bson_strdup (ns);
   /* TODO: check if schema is cached. If we know encryption isn't needed. We
    * can avoid a needless copy. */
   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   ctx->vtable.mongo_op_collinfo = _mongocrypt_ctx_mongo_op_collinfo_encrypt;
   ctx->vtable.mongo_feed_collinfo =
      _mongocrypt_ctx_mongo_feed_collinfo_encrypt;
   ctx->vtable.mongo_done_collinfo =
      _mongocrypt_ctx_mongo_done_collinfo_encrypt;
   ctx->vtable.mongo_op_markings = _mongocrypt_ctx_mongo_op_markings_encrypt;
   ctx->vtable.mongo_feed_markings =
      _mongocrypt_ctx_mongo_feed_markings_encrypt;
   ctx->vtable.mongo_done_markings =
      _mongocrypt_ctx_mongo_done_markings_encrypt;
   ctx->vtable.finalize = _mongocrypt_ctx_encrypt_finalize;
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
static bool
_parse_ciphertext_unowned (_mongocrypt_buffer_t *in,
                           _mongocrypt_ciphertext_t *ciphertext,
                           mongocrypt_status_t *status)
{
   uint32_t offset;

   BSON_ASSERT (in);
   BSON_ASSERT (ciphertext);
   BSON_ASSERT (status);

   offset = 0;

   /* At a minimum, a ciphertext must be 19 bytes:
    * fle_blob_subtype (1) +
    * key_uuid (16) +
    * original_bson_type (1) +
    * ciphertext (> 0)
    */
   if (in->len < 19) {
      CLIENT_ERR ("malformed ciphertext, too small");
      return false;
   }
   ciphertext->blob_subtype = in->data[0];
   offset += 1;
   /* TODO: merge new changes. */
   if (ciphertext->blob_subtype != 1 && ciphertext->blob_subtype != 2) {
      CLIENT_ERR ("malformed ciphertext, expected blob subtype of 1 or 2");
      return false;
   }

   /* TODO: after merging CDRIVER-3003, use _mongocrypt_buffer_init. */
   memset (&ciphertext->key_id, 0, sizeof (ciphertext->key_id));
   ciphertext->key_id.data = in->data + offset;
   ciphertext->key_id.len = 16;
   ciphertext->key_id.subtype = BSON_SUBTYPE_UUID;
   offset += 16;

   ciphertext->original_bson_type = in->data[offset];
   offset += 1;

   memset (&ciphertext->data, 0, sizeof (ciphertext->data));
   ciphertext->data.data = in->data + offset;
   ciphertext->data.len = in->len - offset;

   return true;
}


static bool
_collect_key_from_ciphertext (void *ctx, _mongocrypt_buffer_t *in, mongocrypt_status_t* status)
{
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_ctx_decrypt_t *dctx;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      return false;
   }

   if (!_mongocrypt_key_broker_add_id (&dctx->parent.kb, &ciphertext.key_id)) {
      return _mongocrypt_key_broker_status (&dctx->parent.kb, status);
   }

   return true;
}


static bool
_replace_ciphertext_with_plaintext (void *ctx,
                                    _mongocrypt_buffer_t *in,
                                    bson_value_t *out, mongocrypt_status_t* status)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_buffer_t key_material;
   bson_t wrapper;
   bson_iter_t iter;
   uint32_t bytes_written;
   bool ret = false;

   BSON_ASSERT (ctx);
   BSON_ASSERT (in);
   BSON_ASSERT (out);

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;

   if (!_parse_ciphertext_unowned (in, &ciphertext, status)) {
      goto fail;
   }

   /* look up the key */
   if (!_mongocrypt_key_broker_decrypted_key_material_by_id (
      &dctx->parent.kb, &ciphertext.key_id, &key_material)) {
      /* We allow partial decryption, so this is not an error. */
      _mongocrypt_log (&dctx->parent.crypt->log,
                       MONGOCRYPT_LOG_LEVEL_WARNING,
                       "Missing key, skipping decryption for this ciphertext");
      ret = true;
      goto fail;
   }

   plaintext.len = ciphertext.data.len;
   plaintext.data = bson_malloc0 (plaintext.len);
   plaintext.owned = true;

   if (!_mongocrypt_do_decryption (NULL,
                                   &key_material,
                                   &ciphertext.data,
                                   &plaintext,
                                   &bytes_written,
                                   status)) {
      goto fail;
   }

   plaintext.len = bytes_written;

   bson_init_static (&wrapper, plaintext.data, plaintext.len);
   bson_iter_init_find (&iter, &wrapper, "");
   bson_value_copy (bson_iter_value (&iter), out);
   ret = true;

fail:
   bson_free (plaintext.data);
   return ret;
}


static bool
_mongocrypt_ctx_decrypt_finalize (mongocrypt_ctx_t *ctx,
                                  mongocrypt_binary_t *out)
{
   bson_t as_bson, final;
   bson_iter_t iter;
   _mongocrypt_ctx_decrypt_t *dctx;
   mongocrypt_status_t *status;
   bool res;

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   status = dctx->parent.status;
   _mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson);
   bson_iter_init (&iter, &as_bson);
   bson_init (&final);
   res =
      _mongocrypt_transform_binary_in_bson (_replace_ciphertext_with_plaintext,
                                            dctx,
                                            TRAVERSE_MATCH_CIPHERTEXT,
                                            &iter,
                                            &final,
                                            status);
   if (!res) {
      dctx->parent.state = MONGOCRYPT_CTX_ERROR;
      return false;
   }
   _mongocrypt_buffer_steal_from_bson (&dctx->decrypted_doc, &final);
   out->data = dctx->decrypted_doc.data;
   out->len = dctx->decrypted_doc.len;
   ctx->state = MONGOCRYPT_CTX_DONE;
   return true;
}


bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc)
{
   _mongocrypt_ctx_decrypt_t *dctx;
   bson_t as_bson;
   bson_iter_t iter;

   dctx = (_mongocrypt_ctx_decrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_DECRYPT;
   /* TODO: check if schema is cached. If we know encryption isn't needed. We
    * can avoid a needless copy. */
   _mongocrypt_buffer_copy_from_binary (&dctx->original_doc, doc);
   ctx->vtable.mongo_op_collinfo = _mongocrypt_ctx_mongo_op_invalid;
   ctx->vtable.mongo_feed_collinfo = _mongocrypt_ctx_mongo_feed_invalid;
   ctx->vtable.mongo_done_collinfo = _mongocrypt_ctx_mongo_done_invalid;
   ctx->vtable.mongo_op_markings = _mongocrypt_ctx_mongo_op_invalid;
   ctx->vtable.mongo_feed_markings = _mongocrypt_ctx_mongo_feed_invalid;
   ctx->vtable.mongo_done_markings = _mongocrypt_ctx_mongo_done_invalid;
   ctx->vtable.finalize = _mongocrypt_ctx_decrypt_finalize;

   /* get keys. */
   _mongocrypt_buffer_to_bson (&dctx->original_doc, &as_bson);
   bson_iter_init (&iter, &as_bson);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_ciphertext,
                                             dctx,
                                             TRAVERSE_MATCH_CIPHERTEXT,
                                             &iter,
                                             dctx->parent.status)) {
      ctx->state = MONGOCRYPT_CTX_ERROR;
      return false;
   }

   if (_mongocrypt_key_broker_empty (&ctx->kb)) {
      ctx->state = MONGOCRYPT_CTX_NOTHING_TO_DO;
   } else {
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   }

   return true;
}


bool
mongocrypt_can_skip (mongocrypt_t *crypt, char *ns, uint32_t ns_len)
{
   /* TODO: confer with schema cache. */
   return false;
}
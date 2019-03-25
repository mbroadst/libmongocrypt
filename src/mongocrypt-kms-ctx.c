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


#include "mongocrypt-private.h"
#include "mongocrypt-binary-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-kms-ctx-private.h"
#include "mongocrypt-status-private.h"
#include <kms_message/kms_b64.h>
#include "mongocrypt.h"

/* Before we've read the Content-Length header in an HTTP response,
 * we don't know how many bytes we'll need. So return this value
 * in kms_ctx_bytes_needed until we are fed the Content-Length.
 */
#define DEFAULT_MAX_KMS_BYTE_REQUEST 1024

void
_mongocrypt_kms_ctx_init (mongocrypt_kms_ctx_t *kms,
                          _mongocrypt_buffer_t *key_material,
                          _kms_request_type_t request_type,
                          void *ctx)
{
   kms_request_opt_t *opt;

   kms->req_type = request_type;
   /* create the KMS request. */
   opt = kms_request_opt_new ();
   /* TODO: we might want to let drivers control whether or not we send
      * Connection: close header. Unsure right now. */
   kms_request_opt_set_connection_close (opt, true);

   switch (kms->req_type) {
   case MONGOCRYPT_KMS_ENCRYPT:
      // kms->req =
      //    kms_encrypt_request_new (key_material->data, key_material->len, NULL /* TODO. */, opt);
      break;
   case MONGOCRYPT_KMS_DECRYPT:
      kms->req =
         kms_decrypt_request_new (key_material->data, key_material->len, opt);
      break;
   }

   kms_request_opt_destroy (opt);

   kms->parser = kms_response_parser_new ();
   kms->ctx = ctx;
   kms->status = mongocrypt_status_new ();
   _mongocrypt_buffer_init (&kms->msg);
   kms->msg.data = (uint8_t *) kms_request_get_signed (kms->req);
   kms->msg.len = strlen ((char *) kms->msg.data);
   kms->msg.owned = true;
   _mongocrypt_buffer_init (&kms->result);
}


uint32_t
mongocrypt_kms_ctx_bytes_needed (mongocrypt_kms_ctx_t *kms)
{
   /* TODO: an oddity of kms-message. After retrieving the JSON result, it resets the parser. */
   if (!mongocrypt_status_ok (kms->status) || !_mongocrypt_buffer_empty(&kms->result)) {
      return 0;
   }
   return kms_response_parser_wants_bytes (kms->parser,
                                           DEFAULT_MAX_KMS_BYTE_REQUEST);
}


bool
mongocrypt_kms_ctx_feed (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *bytes)
{
   mongocrypt_status_t *status;

   status = kms->status;
   if (!mongocrypt_status_ok (status)) {
      return false;
   }

   if (bytes->len > mongocrypt_kms_ctx_bytes_needed (kms)) {
      CLIENT_ERR ("KMS response fed too much data");
      return false;
   }

   /* TODO: KMS error handling in CDRIVER-3000? */
   kms_response_parser_feed (kms->parser, bytes->data, bytes->len);

   if (0 == mongocrypt_kms_ctx_bytes_needed (kms)) {
      kms_response_t *response;
      const char *body;
      bson_t body_bson;
      bson_json_reader_t *reader;
      bool ret;
      int reader_ret;
      const char *key;
      bson_error_t bson_error;
      bson_iter_t iter;
      uint32_t b64_strlen;
      char* b64_str;

      ret = false;
      /* Parse out the {en|de}crypted result. */
      response = kms_response_parser_get_response (kms->parser);
      body = kms_response_get_body (response);
      reader = bson_json_data_reader_new (false, 1024);
      /* TODO: extra strlen can be avoided by exposing length in kms-message. */
      bson_json_data_reader_ingest (
         reader, (const uint8_t *) body, strlen (body));
      bson_init (&body_bson);

      reader_ret = bson_json_reader_read (reader, &body_bson, &bson_error);
      if (reader_ret == -1) {
         CLIENT_ERR ("Error reading KMS response: %s", bson_error.message);
         goto fail;
      } else if (reader_ret == 0) {
         CLIENT_ERR ("Could not read JSON document from response");
         goto fail;
      }

      key = (kms->req_type == MONGOCRYPT_KMS_DECRYPT) ? "Plaintext"
                                                      : "CiphertextBlob";

      if (!bson_iter_init_find (&iter, &body_bson, key) ||
          !BSON_ITER_HOLDS_UTF8 (&iter)) {
         CLIENT_ERR ("KMS JSON response does not include string %s", key);
         goto fail;
      }

      b64_str = (char *) bson_iter_utf8 (&iter, &b64_strlen);
      kms->result.data = bson_malloc (b64_strlen + 1);
      kms->result.len =
         kms_message_b64_pton (b64_str, kms->result.data, b64_strlen);
      kms->result.owned = true;
      ret = true;
   fail:
      bson_json_reader_destroy (reader);
      return ret;
   }
   return true;
}


bool
_mongocrypt_kms_ctx_result (mongocrypt_kms_ctx_t *kms, _mongocrypt_buffer_t* out) {
   mongocrypt_status_t *status;

   status = kms->status;
   if (!mongocrypt_status_ok (status)) {
      return false;
   }

   if (mongocrypt_kms_ctx_bytes_needed (kms) > 0) {
      CLIENT_ERR ("KMS response unfinished");
      return false;
   }

   _mongocrypt_buffer_init (out);
   out->data = kms->result.data;
   out->len = kms->result.len;
   return true;
}


bool
mongocrypt_kms_ctx_status (mongocrypt_kms_ctx_t *kms,
                           mongocrypt_status_t *status)
{
   mongocrypt_status_copy_to (kms->status, status);
   return mongocrypt_status_ok (status);
}


void
_mongocrypt_kms_ctx_cleanup (mongocrypt_kms_ctx_t *kms)
{
   if (!kms) {
      return;
   }
   if (kms->req) {
      kms_request_destroy (kms->req);
   }
   if (kms->parser) {
      kms_response_parser_destroy (kms->parser);
   }
   mongocrypt_status_destroy (kms->status);
   _mongocrypt_buffer_cleanup (&kms->msg);
   _mongocrypt_buffer_cleanup (&kms->result);
}

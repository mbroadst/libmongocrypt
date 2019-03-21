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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <bson/bson.h>
#include <mongocrypt.h>

static uint8_t *
_read_json (const char *path, uint32_t *len)
{
   bson_error_t error;
   bson_json_reader_t *reader;
   bson_t as_bson;
   bool ret;
   uint8_t *data;

   reader = bson_json_reader_new_from_file (path, &error);
   if (!reader) {
      fprintf (stderr, "could not open: %s\n", path);
      abort ();
   }
   bson_init (&as_bson);
   if (!bson_json_reader_read (reader, &as_bson, &error)) {
      fprintf (stderr, "could not read json from: %s\n", path);
      abort ();
   }

   return bson_destroy_with_steal (&as_bson, true, len);
}

static uint8_t *
_read_http (const char *path, uint32_t *len)
{
   int fd;
   char *contents = NULL;
   int n_read;
   int filesize = 0;
   char storage[512];
   int i;
   uint8_t *final;

   fd = open (path, O_RDONLY);
   while ((n_read = read (fd, storage, sizeof (storage))) > 0) {
      filesize += n_read;
      contents = bson_realloc (contents, filesize);
      memcpy (contents + (filesize - n_read), storage, n_read);
   }

   if (n_read < 0) {
      fprintf (stderr, "failed to read %s\n", path);
      abort ();
   }

   close (fd);
   *len = 0;

   /* Copy and fix newlines: \n becomes \r\n. */
   final = bson_malloc0 (filesize * 2);
   for (i = 0; i < filesize; i++) {
      if (contents[i] == '\n' && contents[i - 1] != '\r') {
         final[(*len)++] = '\r';
      }
      final[(*len)++] = contents[i];
   }

   bson_free (contents);
   return final;
}

static void
_print_binary_as_bson (mongocrypt_binary_t *binary)
{
   bson_t as_bson;
   char *str;

   bson_init_static (&as_bson,
                     mongocrypt_binary_data (binary),
                     mongocrypt_binary_len (binary));
   str = bson_as_json (&as_bson, NULL);
   printf ("%s\n", str);
   bson_free (str);
}

static void
_print_binary_as_text (mongocrypt_binary_t *binary)
{
   int i;
   uint8_t *ptr;

   ptr = (uint8_t *) mongocrypt_binary_data (binary);
   for (i = 0; i < mongocrypt_binary_len (binary); i++) {
      printf ("%c", (char) *(ptr + i));
   }
   printf ("\n");
}

int
main ()
{
   const char *on_db;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *input, *output;
   uint8_t *input_data[4], *cmd;
   uint32_t input_len[4], cmd_len;
   int input_idx;
   mongocrypt_kms_ctx_t *kms;
   mongocrypt_ctx_state_t state;
   mongocrypt_status_t *status;
   bool done = false;

   cmd = _read_json ("./test/example/command.json", &cmd_len);
   input_data[0] =
      _read_json ("./test/example/list-collections-reply.json", &input_len[0]);
   input_data[1] =
      _read_json ("./test/example/mongocryptd-reply.json", &input_len[1]);
   input_data[2] = _read_json ("./test/example/key-reply.json", &input_len[2]);
   input_data[3] = _read_http ("./test/example/kms-reply.txt", &input_len[3]);

   crypt = mongocrypt_new (NULL);
   ctx = mongocrypt_ctx_new (crypt);

   input = mongocrypt_binary_new_from_data (cmd, cmd_len);
   mongocrypt_ctx_encrypt_init (ctx, "test.test", 9, input);
   mongocrypt_binary_destroy (input);
   status = mongocrypt_status_new ();
   input_idx = 0;
   state = mongocrypt_ctx_state (ctx);

   while (!done) {
      input = mongocrypt_binary_new_from_data (input_data[input_idx],
                                               input_len[input_idx]);
      switch (state) {
      case MONGOCRYPT_CTX_NEED_MONGO:
      case MONGOCRYPT_CTX_NEED_MONGOCRYPTD:
         mongocrypt_ctx_mongo_cmd (ctx, output, &on_db);
         printf ("sending the following to mongo%s (on %s):\n",
                 state == MONGOCRYPT_CTX_NEED_MONGOCRYPTD ? "cryptd" : "",
                 on_db);
         _print_binary_as_bson (output);
         printf ("mocking reply from file:\n");
         _print_binary_as_bson (input);
         mongocrypt_ctx_mongo_reply (ctx, input);
         break;
      case MONGOCRYPT_CTX_NEED_KMS:
         kms = mongocrypt_ctx_next_kms_ctx (ctx, output);
         printf ("\nlibmongocrypt wants to send the following to kms:\n");
         _print_binary_as_text (output);
         printf ("mocking reply from file\n");
         mongocrypt_kms_ctx_feed (kms, input);
         assert (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
         mongocrypt_ctx_kms_ctx_done (ctx, kms);
         break;
      case MONGOCRYPT_CTX_READY:
         mongocrypt_ctx_finalize (ctx, output);
         printf ("\nencrypted command is:");
         _print_binary_as_bson (output);
         break;
      case MONGOCRYPT_CTX_DONE:
         done = true;
         break;
      case MONGOCRYPT_CTX_NOTHING_TO_DO:
         printf ("no encryption was needed\n");
         done = true;
         break;
      case MONGOCRYPT_CTX_ERROR:
         mongocrypt_ctx_status (ctx, status);
         printf ("got error: %s\n", mongocrypt_status_message (status));
         done = true;
         break;
      }
      input_idx++;
      mongocrypt_binary_destroy (input);
      state = mongocrypt_ctx_state (ctx);
   }

   for (input_idx = 0; input_idx < sizeof (input_data) / sizeof (*input_data);
        input_idx++) {
      bson_free (input_data[input_idx]);
   }
   mongocrypt_status_destroy (status);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

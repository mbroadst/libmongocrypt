/*
 * Copyright 2018-present MongoDB, Inc.
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

#include "mongocrypt-binary-private.h"
#include "mongocrypt-buffer-private.h"

mongocrypt_binary_t *
mongocrypt_binary_new (uint8_t *data, uint32_t len)
{
   mongocrypt_binary_t *binary;

   binary = (mongocrypt_binary_t *) bson_malloc0 (sizeof *binary);
   binary->data = data;
   binary->len = len;

   return binary;
}


void
_mongocrypt_binary_to_bson (const mongocrypt_binary_t *binary, bson_t *out)
{
   bson_init_static (out, binary->data, binary->len);
}


const uint8_t *
mongocrypt_binary_data (const mongocrypt_binary_t *binary)
{
   return binary->data;
}


uint32_t
mongocrypt_binary_len (const mongocrypt_binary_t *binary)
{
   return binary->len;
}


void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary)
{
   if (!binary) {
      return;
   }

   bson_free (binary);
}
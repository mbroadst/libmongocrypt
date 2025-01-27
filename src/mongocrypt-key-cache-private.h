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

#ifndef MONGOCRYPT_KEY_CACHE_PRIVATE_H
#define MONGOCRYPT_KEY_CACHE_PRIVATE_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-mutex-private.h"
#include "mongocrypt-status-private.h"

typedef struct {
   _mongocrypt_buffer_t id;
   _mongocrypt_buffer_t key_material;
} _mongocrypt_key_t;

bool
_mongocrypt_key_parse_owned (const bson_t *bson,
                             _mongocrypt_key_t *out,
                             mongocrypt_status_t *status);

void
_mongocrypt_key_cleanup (_mongocrypt_key_t *key);


/* Dear reader, please have a laugh at the "key cache". */
typedef struct {
   bson_t *key_bson;
   _mongocrypt_key_t key;
   bool used;
} _mongocrypt_keycache_entry_t;

typedef bool (*mongocrypt_key_decrypt_fn) (_mongocrypt_key_t *key,
                                           mongocrypt_status_t *status,
                                           void *ctx);

typedef struct {
   mongocrypt_key_decrypt_fn decrypt_key;
   void *decrypt_key_ctx;

   mongocrypt_mutex_t mutex;
   _mongocrypt_keycache_entry_t keycache[64];
} _mongocrypt_key_cache_t;


_mongocrypt_key_cache_t *
_mongocrypt_key_cache_new (mongocrypt_key_decrypt_fn decrypt_key,
                           void *decrypt_key_ctx);

void
_mongocrypt_key_cache_destroy (_mongocrypt_key_cache_t *cache);

bool
_mongocrypt_key_cache_add (_mongocrypt_key_cache_t *cache,
                           _mongocrypt_buffer_t *docs,
                           uint32_t num_docs,
                           mongocrypt_status_t *status);


const _mongocrypt_key_t *
_mongocrypt_key_cache_get_by_id (_mongocrypt_key_cache_t *cache,
                                 const _mongocrypt_buffer_t *uuid,
                                 mongocrypt_status_t *status);


void
_mongocrypt_key_cache_dump (_mongocrypt_key_cache_t *cache);


int
_mongocrypt_key_cache_size (_mongocrypt_key_cache_t *cache);


#endif /* MONGOCRYPT_KEY_CACHE_PRIVATE_H */

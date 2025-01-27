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

#ifndef MONGOCRYPT_BINARY_PRIVATE_H
#define MONGOCRYPT_BINARY_PRIVATE_H

#include <bson/bson.h>

#include "mongocrypt-binary.h"

struct _mongocrypt_binary_t {
   uint8_t *data;
   uint32_t len;
};

void
_mongocrypt_binary_to_bson (const mongocrypt_binary_t *binary, bson_t *out);


#endif /* MONGOCRYPT_BINARY_PRIVATE_H */

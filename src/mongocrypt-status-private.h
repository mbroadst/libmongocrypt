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

#ifndef MONGOCRYPT_STATUS_PRIVATE_H
#define MONGOCRYPT_STATUS_PRIVATE_H

#include "mongocrypt-status.h"

#define MONGOCRYPT_STATUS_MSG_LEN 1024

struct _mongocrypt_status_t {
   mongocrypt_error_type_t type;
   uint32_t code;
   char message[MONGOCRYPT_STATUS_MSG_LEN];
};


void
mongocrypt_status_copy_to (mongocrypt_status_t *src, mongocrypt_status_t *dst);

void
mongocrypt_status_reset (mongocrypt_status_t *status);

#endif /* MONGOCRYPT_STATUS_PRIVATE_H */

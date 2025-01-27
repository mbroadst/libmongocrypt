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

#ifndef MONGOCRYPT_STATUS_H
#define MONGOCRYPT_STATUS_H

#include <stdint.h>

#include "mongocrypt-export.h"

typedef enum {
   MONGOCRYPT_ERROR_TYPE_NONE = 0,
   MONGOCRYPT_ERROR_TYPE_MONGOCRYPTD,
   MONGOCRYPT_ERROR_TYPE_KMS,
   MONGOCRYPT_ERROR_TYPE_CLIENT
} mongocrypt_error_type_t;

typedef struct _mongocrypt_status_t mongocrypt_status_t;


MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_status_new (void);


MONGOCRYPT_EXPORT
void
mongocrypt_status_destroy (mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
mongocrypt_error_type_t
mongocrypt_status_error_type (const mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
uint32_t
mongocrypt_status_code (const mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
const char *
mongocrypt_status_message (const mongocrypt_status_t *status);

MONGOCRYPT_EXPORT
bool
mongocrypt_status_ok (const mongocrypt_status_t *status);


#endif /* MONGOCRYPT_STATUS_H */

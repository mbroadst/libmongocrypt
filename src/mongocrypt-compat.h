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
#ifndef MONGOCRYPT_COMPAT_H
#define MONGOCRYPT_COMPAT_H

/* Utilities for cross-platform and C89 compatibility */

/* TODO: check for stdbool in cmake. */
#ifndef BSON_HAVE_STDBOOL_H
#define BSON_HAVE_STDBOOL_H 1
/* Copied from bson-compat.h from the C driver. */
#include <stdint.h>
#ifdef BSON_HAVE_STDBOOL_H
#include <stdbool.h>
#elif !defined(__bool_true_false_are_defined)
#ifndef __cplusplus
typedef signed char bool;
#define false 0
#define true 1
#endif
#define __bool_true_false_are_defined 1
#endif

#endif
#endif /* MONGOCRYPT_COMPAT_H */
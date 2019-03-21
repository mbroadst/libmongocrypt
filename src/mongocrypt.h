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
#ifndef MONGOCCRYPT_H
#define MONGOCCRYPT_H

/** @file mongocrypt.h The top-level handle to libmongocrypt. */

#include "mongocrypt-export.h"
#include "mongocrypt-compat.h"

#define MONGOCRYPT_VERSION "0.3.0"

/**
 * Returns the version string x.y.z for libmongocrypt.
 *
 * @returns the version string x.y.z for libmongocrypt.
 */
MONGOCRYPT_EXPORT
const char *
mongocrypt_version (void);


/**
 * A non-owning view of a byte buffer.
 *
 * Functions returning a mongocrypt_binary_t* expect it to be destroyed with
 * mongocrypt_binary_destroy.
 *
 * Functions taking a mongocrypt_binary_t* argument may either copy or keep a
 * pointer to the data. See individual function documentation.
*/
typedef struct _mongocrypt_binary_t mongocrypt_binary_t;


/**
 * Create a new non-owning view of a buffer (data + length).
 *
 * @returns A new mongocrypt_binary_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_binary_new (void);

/**
 * Create a new non-owning view of a buffer (data + length).
 *
 * @param data A pointer to an array of bytes. This is not copied. @data must
 * outlive the binary object.
 * @param len The length of the @data array.
 *
 * @returns A new mongocrypt_binary_t.
 */
MONGOCRYPT_EXPORT
mongocrypt_binary_t *
mongocrypt_binary_new_from_data (uint8_t *data, uint32_t len);


/**
 * Get a pointer to the referenced data.
 *
 * @param binary The mongocrypt_binary_t from which to retrieve the data.
 *
 * @returns A pointer to the referenced data.
 */
MONGOCRYPT_EXPORT
const uint8_t *
mongocrypt_binary_data (const mongocrypt_binary_t *binary);


/**
 * Get the length of the referenced data.
 *
 * @param binary The mongocrypt_binary_t from which to retrieve the length.
 *
 * @returns The length of the referenced data.
 */
MONGOCRYPT_EXPORT
uint32_t
mongocrypt_binary_len (const mongocrypt_binary_t *binary);


/**
 * Free the mongocrypt_binary_t. Does not free the referenced data.
 *
 * @param binary The mongocrypt_binary_t destroy.
 */
MONGOCRYPT_EXPORT
void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary);


typedef struct _mongocrypt_status_t mongocrypt_status_t;


typedef enum {
   MONGOCRYPT_STATUS_OK,
   MONGOCRYPT_STATUS_ERROR_CLIENT,
   MONGOCRYPT_STATUS_ERROR_KMS
} mongocrypt_status_type_t;


MONGOCRYPT_EXPORT
mongocrypt_status_t *
mongocrypt_status_new (void);


MONGOCRYPT_EXPORT
void
mongocrypt_status_destroy (mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
mongocrypt_status_type_t
mongocrypt_status_type (mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
uint32_t
mongocrypt_status_code (mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
const char *
mongocrypt_status_message (mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
bool
mongocrypt_status_ok (mongocrypt_status_t *status);


typedef struct _mongocrypt_opts_t mongocrypt_opts_t;


typedef enum {
   MONGOCRYPT_AWS_REGION,
   MONGOCRYPT_AWS_SECRET_ACCESS_KEY,
   MONGOCRYPT_AWS_ACCESS_KEY_ID,
   MONGOCRYPT_LOG_FN,
   MONGOCRYPT_LOG_CTX
} mongocrypt_opt_t;


MONGOCRYPT_EXPORT
mongocrypt_opts_t *
mongocrypt_opts_new (void);


MONGOCRYPT_EXPORT
void
mongocrypt_opts_set_opt (mongocrypt_opts_t *opts,
                         mongocrypt_opt_t opt,
                         void *value);


MONGOCRYPT_EXPORT
void
mongocrypt_opts_destroy (mongocrypt_opts_t *opts);


typedef enum {
   MONGOCRYPT_LOG_LEVEL_FATAL,
   MONGOCRYPT_LOG_LEVEL_ERROR,
   MONGOCRYPT_LOG_LEVEL_WARNING,
   MONGOCRYPT_LOG_LEVEL_INFO,
   MONGOCRYPT_LOG_LEVEL_TRACE
} mongocrypt_log_level_t;


/**
 * The log callback function.
 */
typedef void (*mongocrypt_log_fn_t) (mongocrypt_log_level_t level,
                                     const char *message,
                                     void *ctx);


/**
 * The top-level handle to libmongocrypt.
 *
 * Create a mongocrypt_t handle to perform operations within libmongocrypt:
 * encryption, decryption, registering log callbacks, etc.
 *
 * Functions on a mongocrypt_t are thread safe, though functions on derived
 * handle (e.g. mongocrypt_encryptor_t) are not and must be owned by a single
 * thread. See each handle's documentation for thread-safety considerations.
 *
 * Multiple mongocrypt_t handles may be created.
 */
typedef struct _mongocrypt_t mongocrypt_t;


/**
 * Create a new mongocrypt_t handle.
 *
 * @returns A new mongocrypt_t handle.
 */
MONGOCRYPT_EXPORT
mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts);


MONGOCRYPT_EXPORT
bool
mongocrypt_status (mongocrypt_t *crypt, mongocrypt_status_t *out);


MONGOCRYPT_EXPORT
void
mongocrypt_destroy (mongocrypt_t *crypt);


/* A context manages the state machine for encryption or decryption. */
typedef struct _mongocrypt_ctx_t mongocrypt_ctx_t;


MONGOCRYPT_EXPORT
mongocrypt_ctx_t *
mongocrypt_ctx_new (mongocrypt_t *crypt);


MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_status (mongocrypt_ctx_t *ctx, mongocrypt_status_t *out);


/**
 * Initialize a handle for encryption. @cmd is the command to be encrypted.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *ns,
                             uint32_t ns_len,
                             mongocrypt_binary_t *cmd);


/**
 * Initialize a handle for decryption. @doc is a document to be decrypted.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_decrypt_init (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *doc);


typedef enum {
   MONGOCRYPT_CTX_ERROR,
   MONGOCRYPT_CTX_NOTHING_TO_DO,
   MONGOCRYPT_CTX_NEED_MONGO,
   MONGOCRYPT_CTX_NEED_MONGO_KEY_VAULT,
   MONGOCRYPT_CTX_NEED_MONGOCRYPTD,
   MONGOCRYPT_CTX_NEED_KMS,
   MONGOCRYPT_CTX_READY, /* ready for encryption/decryption */
   MONGOCRYPT_CTX_DONE
} mongocrypt_ctx_state_t;

MONGOCRYPT_EXPORT
mongocrypt_ctx_state_t
mongocrypt_ctx_state (mongocrypt_ctx_t *ctx);


/* Encapsulates an operation to run on a MongoDB server. */
typedef struct _mongocrypt_mongo_op_t mongocrypt_mongo_op_t;


typedef enum {
   MONGOCRYPT_OP_LIST_COLLECTIONS,
   MONGOCRYPT_OP_FIND,
   MONGOCRYPT_OP_RUN_COMMAND
} mongocrypt_mongo_op_type_t;


/**
 * Get the mongo operation to run. Call this when the mongocrypt_ctx_t
 * is in MONGOCRYPT_CTX_NEED_MONGO, MONGOCRYPT_CTX_NEED_MONGO_KEY_VAULT,
 * or MONGOCRYPT_CTX_NEED_MONGOCRYPTD.
 *
 * op_bson is a BSON document to be used for the operation.
 * If optype_out == MONGOCRYPT_OP_LIST_COLLECTIONS it is a filter
 * if optype_out == MONGOCRYPT_OP_FIND, it is a filter
 * If optype_out == MONGOCRYPT_OP_RUN_COMMAND it is a command.
 */
MONGOCRYPT_EXPORT
mongocrypt_mongo_op_t *
mongocrypt_ctx_mongo_op (mongocrypt_ctx_t *ctx,
                         mongocrypt_binary_t *out,
                         mongocrypt_mongo_op_type_t *op_type_out,
                         mongocrypt_binary_t *op_bson);


/**
 * Feed BSON back. This is either the runCommand reply, or a document from a
 * cursor.
 */
MONGOCRYPT_EXPORT
bool
mongocrypt_mongo_op_feed (mongocrypt_mongo_op_t *op,
                          mongocrypt_binary_t *reply);


MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_mongo_op_done (mongocrypt_ctx_t *ctx, mongocrypt_mongo_op_t *op);


typedef struct _mongocrypt_kms_ctx_t mongocrypt_kms_ctx_t;


/**
 * Get the next KMS handle. Driver may use grab multiple concurrent handles to
 * fan-out KMS HTTP messages.
 */
MONGOCRYPT_EXPORT
mongocrypt_kms_ctx_t *
mongocrypt_ctx_next_kms_ctx (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *msg);


MONGOCRYPT_EXPORT
uint32_t
mongocrypt_kms_ctx_bytes_needed (mongocrypt_kms_ctx_t *kms);


MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_feed (mongocrypt_kms_ctx_t *kms, mongocrypt_binary_t *data);


MONGOCRYPT_EXPORT
bool
mongocrypt_kms_ctx_status (mongocrypt_kms_ctx_t *kms,
                           mongocrypt_status_t *status);


MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_kms_ctx_done (mongocrypt_ctx_t *ctx, mongocrypt_kms_ctx_t *kms);


MONGOCRYPT_EXPORT
bool
mongocrypt_ctx_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out);


MONGOCRYPT_EXPORT
void
mongocrypt_ctx_destroy (mongocrypt_ctx_t *ctx);


#endif /* MONGOCRYPT_H */

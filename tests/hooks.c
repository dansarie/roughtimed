/* hooks.h

   Copyright (C) 2019-2016 Marcus Dansarie <marcus@dansarie.se>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <openssl/evp.h>
#endif

#include <stdint.h>
#include <time.h>

#define TEST_CODE
#include "hooks.h"

#define CALLS_VAR(F) g_##F##_calls
#define FAILON_VAR(F) g_##F##_failon
#define FAILVAL_VAR(F) g_##F##_failval

#define WRAP_VARS(F, T)\
  int64_t CALLS_VAR(F) = 0;   /* Counts number of calls to F. */ \
  int64_t FAILON_VAR(F) = -1; /* Which call to F that should fail. */\
  T FAILVAL_VAR(F);           /* Which value should be returned on failure. */

/**
 * Macro for the internal logic of a wrap function.
 * @param F name of the wrapped function.
 * @param ... arguments to the wrapped function.
 */
#define WRAP_FUNCTION(F, ...)\
  CALLS_VAR(F) += 1;\
  if (FAILON_VAR(F) == 0 || CALLS_VAR(F) == FAILON_VAR(F)) {\
    return FAILVAL_VAR(F);\
  }\
  return F(__VA_ARGS__);

/**
 * Macro for the internal logic of a wrap function.
 * @param F name of the wrapped function.
 * @param S a statement that will be executed on failure.
 * @param ... arguments to the wrapped function.
 */
#define WRAP_FUNCTION_SPECIAL(F, S, ...)\
  CALLS_VAR(F) += 1;\
  if (FAILON_VAR(F) == 0 || CALLS_VAR(F) == FAILON_VAR(F)) {\
    S;\
    return FAILVAL_VAR(F);\
  }\
  return F(__VA_ARGS__);

/**
 * Macro for the function that sets when F should fail.
 * @param i sets up to fail on exactly the ith call. A value of zero causes it to always fail.
 * @param T the type of the value parameter.
 * Negative values mean that it never fails.
 */
#define FAIL_FUNCTION(F, T)\
  void fail_##F(int64_t i, T val) {\
    CALLS_VAR(F) = 0;\
    FAILON_VAR(F) = i;\
    FAILVAL_VAR(F) = val;\
  }

WRAP_VARS(gmtime_r, struct tm*)
FAIL_FUNCTION(gmtime_r, struct tm*)
struct tm *test_gmtime_r(const time_t *restrict timep, struct tm *restrict result) {
  WRAP_FUNCTION(gmtime_r, timep, result)
}

WRAP_VARS(EVP_PKEY_new_raw_private_key, EVP_PKEY*)
FAIL_FUNCTION(EVP_PKEY_new_raw_private_key, EVP_PKEY*)
EVP_PKEY *test_EVP_PKEY_new_raw_private_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen) {
  WRAP_FUNCTION(EVP_PKEY_new_raw_private_key, type, e, key, keylen)
}

WRAP_VARS(EVP_PKEY_new_raw_public_key, EVP_PKEY*)
FAIL_FUNCTION(EVP_PKEY_new_raw_public_key, EVP_PKEY*)
EVP_PKEY *test_EVP_PKEY_new_raw_public_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen) {
  WRAP_FUNCTION(EVP_PKEY_new_raw_public_key, type, e, key, keylen)
}

WRAP_VARS(EVP_PKEY_CTX_new, EVP_PKEY_CTX*)
FAIL_FUNCTION(EVP_PKEY_CTX_new, EVP_PKEY_CTX*)
EVP_PKEY_CTX *test_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e) {
  WRAP_FUNCTION(EVP_PKEY_CTX_new, pkey, e)
}

WRAP_VARS(EVP_MD_CTX_new, EVP_MD_CTX*)
FAIL_FUNCTION(EVP_MD_CTX_new, EVP_MD_CTX*)
EVP_MD_CTX *test_EVP_MD_CTX_new(void) {
  WRAP_FUNCTION(EVP_MD_CTX_new, /* void */)
}

WRAP_VARS(EVP_DigestSignInit, int)
FAIL_FUNCTION(EVP_DigestSignInit, int)
int test_EVP_DigestSignInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey) {
  WRAP_FUNCTION(EVP_DigestSignInit, ctx, pctx, type, e, pkey)
}

size_t g_EVP_DigestSign_siglen = 65;
void EVP_DigestSign_set_siglen(size_t *siglen) {
  *siglen = g_EVP_DigestSign_siglen;
}

WRAP_VARS(EVP_DigestSign, int)
FAIL_FUNCTION(EVP_DigestSign, int)
int test_EVP_DigestSign(
    EVP_MD_CTX *ctx,
    unsigned char *sig,
    size_t *siglen,
    const unsigned char *tbs,
    size_t tbslen) {
  WRAP_FUNCTION_SPECIAL(EVP_DigestSign, EVP_DigestSign_set_siglen(siglen), ctx, sig, siglen, tbs, tbslen)
}

WRAP_VARS(EVP_DigestVerifyInit, int)
FAIL_FUNCTION(EVP_DigestVerifyInit, int)
int test_EVP_DigestVerifyInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey) {
  WRAP_FUNCTION(EVP_DigestVerifyInit, ctx, pctx, type, e, pkey)
}

WRAP_VARS(EVP_DigestVerify, int)
FAIL_FUNCTION(EVP_DigestVerify, int)
int test_EVP_DigestVerify(
    EVP_MD_CTX *ctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen) {
  WRAP_FUNCTION(EVP_DigestVerify, ctx, sig, siglen, tbs, tbslen)
}

size_t g_EVP_PKEY_get_raw_public_key_len = 33;
void EVP_PKEY_get_raw_public_key_set_len(size_t *len) {
  *len = g_EVP_PKEY_get_raw_public_key_len;
}

WRAP_VARS(EVP_PKEY_get_raw_public_key, int)
FAIL_FUNCTION(EVP_PKEY_get_raw_public_key, int)
int test_EVP_PKEY_get_raw_public_key(
    const EVP_PKEY *pkey,
    unsigned char *pub,
    size_t *len) {
  WRAP_FUNCTION_SPECIAL(EVP_PKEY_get_raw_public_key, EVP_PKEY_get_raw_public_key_set_len(len), pkey, pub, len)
}

WRAP_VARS(EVP_DecodeBlock, size_t)
FAIL_FUNCTION(EVP_DecodeBlock, size_t)
int test_EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n) {
  WRAP_FUNCTION(EVP_DecodeBlock, t, f, n)
}

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

#ifdef TEST_CODE
#undef TESTING
#include <time.h>
#include <openssl/evp.h>

/* Declare the fail functions that are used to indicate when a hooked function should fail. */
#define FAIL_FUNCTION_DECLARATION(F, T) void fail_##F(int64_t i, T val)
FAIL_FUNCTION_DECLARATION(gmtime_r, struct tm*);
FAIL_FUNCTION_DECLARATION(EVP_PKEY_new_raw_private_key, EVP_PKEY*);
FAIL_FUNCTION_DECLARATION(EVP_PKEY_new_raw_public_key, EVP_PKEY*);
FAIL_FUNCTION_DECLARATION(EVP_PKEY_CTX_new, EVP_PKEY_CTX*);
FAIL_FUNCTION_DECLARATION(EVP_MD_CTX_new, EVP_MD_CTX*);
FAIL_FUNCTION_DECLARATION(EVP_DigestSignInit, int);
FAIL_FUNCTION_DECLARATION(EVP_DigestSign, int);
FAIL_FUNCTION_DECLARATION(EVP_DigestVerifyInit, int);
FAIL_FUNCTION_DECLARATION(EVP_DigestVerify, int);
FAIL_FUNCTION_DECLARATION(EVP_PKEY_get_raw_public_key, int);
FAIL_FUNCTION_DECLARATION(EVP_DecodeBlock, size_t);
#undef FAIL_FUNCTION_DECLARATION
#endif

#ifdef TESTING
#include <time.h>
#include <openssl/evp.h>

/* Declare the wrapper functions. */
struct tm *test_gmtime_r(const time_t *restrict timep, struct tm *restrict result);

EVP_PKEY *test_EVP_PKEY_new_raw_private_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen);

EVP_PKEY *test_EVP_PKEY_new_raw_public_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen);

EVP_PKEY_CTX *test_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);

EVP_MD_CTX *test_EVP_MD_CTX_new(void);

int test_EVP_DigestSignInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey);

int test_EVP_DigestSign(
    EVP_MD_CTX *ctx,
    unsigned char *sig,
    size_t *siglen,
    const unsigned char *tbs,
    size_t tbslen);

int test_EVP_DigestVerifyInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey);

int test_EVP_DigestVerify(
    EVP_MD_CTX *ctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen);

int test_EVP_PKEY_get_raw_public_key(
    const EVP_PKEY *pkey,
    unsigned char *pub,
    size_t *len);

int test_EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

/* Define the hook macros. */
#define gmtime_r test_gmtime_r
#define EVP_PKEY_new_raw_private_key test_EVP_PKEY_new_raw_private_key
#define EVP_PKEY_new_raw_public_key test_EVP_PKEY_new_raw_public_key
#define EVP_PKEY_CTX_new test_EVP_PKEY_CTX_new
#define EVP_MD_CTX_new test_EVP_MD_CTX_new
#define EVP_DigestSignInit test_EVP_DigestSignInit
#define EVP_DigestSign test_EVP_DigestSign
#define EVP_DigestVerifyInit test_EVP_DigestVerifyInit
#define EVP_DigestVerify test_EVP_DigestVerify
#define EVP_PKEY_get_raw_public_key test_EVP_PKEY_get_raw_public_key
#define EVP_DecodeBlock test_EVP_DecodeBlock
#endif

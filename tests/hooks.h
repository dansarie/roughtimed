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

#ifndef HOOKS_H
#define HOOKS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <openssl/evp.h>
#include "../src/roughtime_common.h"

typedef struct {
  /* From roughtime_common.h */
  roughtime_result_t (*get_header_tag)(
      const roughtime_header_t *restrict header,
      uint32_t tag,
      uint32_t *restrict offset,
      uint32_t *restrict length);
  roughtime_result_t (*parse_roughtime_header)(
      const uint8_t *restrict message,
      uint32_t message_len,
      roughtime_header_t *restrict header);
  roughtime_result_t (*verify_signature)(
      const uint8_t *restrict data,
      uint32_t len,
      const uint8_t *restrict context,
      uint32_t context_len,
      const uint8_t *restrict signature,
      const uint8_t *restrict public_key);
  /* From stdlib.h */
  void* (*malloc)(size_t size);
  /* From time.h. */
  struct tm* (*gmtime_r)(
      const time_t *restrict timep,
      struct tm *restrict result);
  /* From openssl/evp.h */
  int (*EVP_DecodeBlock)(
      unsigned char *t,
      const unsigned char *f,
      int n);
  int (*EVP_DigestSign)(
      EVP_MD_CTX *ctx,
      unsigned char *sig,
      size_t *siglen,
      const unsigned char *tbs,
      size_t tbslen);
  int (*EVP_DigestSignInit)(
      EVP_MD_CTX *ctx,
      EVP_PKEY_CTX **pctx,
      const EVP_MD *type,
      ENGINE *e,
      EVP_PKEY *pkey);
  int (*EVP_DigestVerify)(
      EVP_MD_CTX *ctx,
      const unsigned char *sig,
      size_t siglen,
      const unsigned char *tbs,
      size_t tbslen);
  int (*EVP_DigestVerifyInit)(
      EVP_MD_CTX *ctx,
      EVP_PKEY_CTX **pctx,
      const EVP_MD *type,
      ENGINE *e,
      EVP_PKEY *pkey);
  EVP_MD_CTX* (*EVP_MD_CTX_new)(void);
  void (*EVP_MD_CTX_set_pkey_ctx)(
      EVP_MD_CTX *ctx,
      EVP_PKEY_CTX *pctx);
  EVP_PKEY_CTX* (*EVP_PKEY_CTX_new)(
      EVP_PKEY *pkey,
      ENGINE *e);
  int (*EVP_PKEY_get_raw_public_key)(
      const EVP_PKEY *pkey,
      unsigned char *pub,
      size_t *len);
  EVP_PKEY* (*EVP_PKEY_new_raw_private_key)(
      int type,
      ENGINE *e,
      const unsigned char *key,
      size_t keylen);
  EVP_PKEY* (*EVP_PKEY_new_raw_public_key)(
      int type,
      ENGINE *e,
      const unsigned char *key,
      size_t keylen);
} Rtfun;

extern Rtfun rtfun;

void rtfun_reset(void);

#endif /* HOOKS_H */

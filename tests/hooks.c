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
#endif

#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>

#include "hooks.h"

#define RTFUN_INIT {\
  .get_header_tag = get_header_tag,\
  .parse_roughtime_header = parse_roughtime_header,\
  .verify_signature = verify_signature,\
  .malloc = malloc,\
  .gmtime_r = gmtime_r,\
  .EVP_DecodeBlock = EVP_DecodeBlock,\
  .EVP_DigestSign = EVP_DigestSign,\
  .EVP_DigestSignInit = EVP_DigestSignInit,\
  .EVP_DigestVerify = EVP_DigestVerify,\
  .EVP_DigestVerifyInit = EVP_DigestVerifyInit,\
  .EVP_MD_CTX_new = EVP_MD_CTX_new,\
  .EVP_MD_CTX_set_pkey_ctx = EVP_MD_CTX_set_pkey_ctx,\
  .EVP_PKEY_CTX_new = EVP_PKEY_CTX_new,\
  .EVP_PKEY_get_raw_public_key = EVP_PKEY_get_raw_public_key,\
  .EVP_PKEY_new_raw_private_key = EVP_PKEY_new_raw_private_key,\
  .EVP_PKEY_new_raw_public_key = EVP_PKEY_new_raw_public_key\
}
Rtfun rtfun = RTFUN_INIT;
const Rtfun rtfun_reset_val = RTFUN_INIT;

void rtfun_reset(void) {
  rtfun = rtfun_reset_val;
}

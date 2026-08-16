/* roughtime_common.c

   Copyright (C) 2019-2026 Marcus Dansarie <marcus@dansarie.se>

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

#include <ctype.h>
#include <endian.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "roughtime_common.h"

#include "hooks.h"

const uint32_t CERTIFICATE_CONTEXT_LEN = 34;
const uint32_t SIGNED_RESPONSE_CONTEXT_LEN = 32;
const uint8_t *const CERTIFICATE_CONTEXT = (uint8_t*)"RoughTime v1 delegation signature";
const uint8_t *const SIGNED_RESPONSE_CONTEXT = (uint8_t*)"RoughTime v1 response signature";

void trim(char *str) {
  ssize_t p = 0;
  while (str[p] != '\0' && isspace(str[p])) {
    p += 1;
  }
  size_t len = strlen(str) - p;
  memmove(str, str + p, len + 1);
  if (len == 0) {
    return;
  }
  for (p = len - 1; isspace(str[p]); p--) {
    str[p] = '\0';
  }
}

uint32_t str_to_tag(const char *str) {
  if (str == NULL) {
    return 0;
  }
  uint32_t ret = 0;
  for (int i = 0; i < 4; i++) {
    if (str[i] == '\0') {
      return ret;
    }
    ret |= str[i] << i * 8;
  }
  return ret;
}

roughtime_result_t create_roughtime_message(
    uint8_t *restrict message,
    uint32_t *restrict size,
    uint32_t num_tags,
    ...) {
  va_list ap;
  va_start(ap, num_tags);
  roughtime_result_t res = create_roughtime_message_va(
      message,
      size,
      num_tags,
      ap);
  va_end(ap);
  return res;
}

roughtime_result_t create_roughtime_message_va(
    uint8_t *restrict message,
    uint32_t *restrict size,
    uint32_t num_tags,
    va_list ap) {

  if (message == NULL || size == NULL || num_tags == 0) {
    if (size != NULL) {
      *size = 0;
    }
    return ROUGHTIME_BAD_ARGUMENT;
  }

  uint32_t *header = (uint32_t*)message;

  if (*size < num_tags * 8) {
    *size = 0;
    return ROUGHTIME_BAD_ARGUMENT;
  }

  uint32_t tmp = htole32(num_tags);
  memcpy(header, &tmp, sizeof(uint32_t));

  const uint32_t header_len = num_tags * 8;
  uint32_t offset = 0;

  uint32_t last_tag = 0;
  for (uint32_t i = 0; i < num_tags; i++) {
    if (i != 0) {
      tmp = htole32(offset);
      memcpy(header + i, &tmp, sizeof(uint32_t));
    }
    uint32_t tag = str_to_tag(va_arg(ap, char*));
    /* Fail if tags are not sorted. */
    if (tag <= last_tag) {
      va_end(ap);
      *size = 0;
      return ROUGHTIME_BAD_ARGUMENT;
    }
    last_tag = tag;
    tmp = htole32(tag);
    memcpy(header + num_tags + i, &tmp, sizeof(uint32_t));
    uint32_t field_size = va_arg(ap, uint32_t);
    if (field_size % 4 != 0 || header_len + offset + field_size > *size) {
      va_end(ap);
      *size = 0;
      return ROUGHTIME_BAD_ARGUMENT;
    }
    uint32_t *ptr = va_arg(ap, uint32_t*);
    memcpy(message + header_len + offset, ptr, field_size);
    offset += field_size;
  }

  *size = offset + header_len;
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t parse_roughtime_header(
    const uint8_t *restrict message,
    uint32_t message_len,
    roughtime_header_t *restrict header) {

  if (message == NULL || message_len < 12 || message_len % 4 != 0 || header == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  memset(header, 0, sizeof(roughtime_header_t));
  memcpy(&header->num_tags, message, sizeof(uint32_t));
  header->num_tags = le32toh(header->num_tags);
  uint32_t header_len = header->num_tags * 8;
  if (header->num_tags == 0
      || header_len > message_len
      || header->num_tags > ROUGHTIME_HEADER_MAX_TAGS) {
    return ROUGHTIME_FORMAT_ERROR;
  }

  for (uint32_t i = 0; i < header->num_tags; i++) {
    if (i == 0) {
      header->offsets[i] = header_len;
    } else {
      memcpy(
          &header->offsets[i],
          message + i * sizeof(uint32_t),
          sizeof(uint32_t));
      header->offsets[i] = le32toh(header->offsets[i]) + header_len;
      if (header->offsets[i] % 4 != 0
          || header->offsets[i] < header->offsets[i - 1]
          || header->offsets[i] > message_len) {
        return ROUGHTIME_FORMAT_ERROR;
      }
      header->lengths[i - 1] = header->offsets[i] - header->offsets[i - 1];
    }
    memcpy(
        &header->tags[i],
        message + (i + header->num_tags) * 4,
        sizeof(uint32_t));
    header->tags[i] = le32toh(header->tags[i]);
    /* Check for unsorted or duplicate tags. */
    if (i > 0 && header->tags[i] <= header->tags[i - 1]) {
      return ROUGHTIME_FORMAT_ERROR;
    }
  }
  header->lengths[header->num_tags - 1] = message_len - header->offsets[header->num_tags - 1];
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t get_header_tag(
    const roughtime_header_t *restrict header,
    uint32_t tag,
    uint32_t *restrict offset,
    uint32_t *restrict length) {

  if (header == NULL
      || offset == NULL
      || length == NULL
      || header->num_tags > ROUGHTIME_HEADER_MAX_TAGS) {
    if (offset != NULL) {
      *offset = 0;
    }
    if (length != NULL) {
      *length = 0;
    }
    return ROUGHTIME_BAD_ARGUMENT;
  }

  for (uint32_t i = 0; i < header->num_tags; i++) {
    if (header->tags[i] == tag) {
      *offset = header->offsets[i];
      *length = header->lengths[i];
      return ROUGHTIME_SUCCESS;
    }
  }
  *offset = 0;
  *length = 0;
  return ROUGHTIME_NOT_FOUND;
}

roughtime_result_t timestamp_to_time(
    time_t timestamp,
    uint32_t *restrict year,
    uint32_t *restrict month,
    uint32_t *restrict day,
    uint32_t *restrict hour,
    uint32_t *restrict minute,
    uint32_t *restrict second) {

  roughtime_result_t err = ROUGHTIME_SUCCESS;
  RETURN_IF(year == NULL
      || month == NULL
      || day == NULL
      || hour == NULL
      || minute == NULL
      || second == NULL,
      ROUGHTIME_BAD_ARGUMENT,
      "NULL argument to timestamp_to_time.");

  struct tm ts = {0};
  RETURN_IF(
      rtfun.gmtime_r(&timestamp, &ts) != &ts,
      ROUGHTIME_INTERNAL_ERROR,
      "gmtime_r returned error.");
  *year   = ts.tm_year  + 1900;
  *month  = ts.tm_mon   + 1;
  *day    = ts.tm_mday;
  *hour   = ts.tm_hour;
  *minute = ts.tm_min;
  *second = ts.tm_sec;

error:
  if (err != ROUGHTIME_SUCCESS) {
    if (year != NULL) {
      *year = 0;
    }
    if (month != NULL) {
      *month = 0;
    }
    if (day != NULL) {
      *day = 0;
    }
    if (hour != NULL) {
      *hour = 0;
    }
    if (minute != NULL) {
      *minute = 0;
    }
    if (second != NULL) {
      *second = 0;
    }
  }
  return err;
}

roughtime_result_t verify_signature(
    const uint8_t *restrict data,
    uint32_t len,
    const uint8_t *restrict context,
    uint32_t context_len,
    const uint8_t *restrict signature,
    const uint8_t *restrict public_key) {
  if (data == NULL
      || len == 0
      || signature == NULL
      || public_key == NULL
      || (context == NULL && context_len > 0)) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *ctx = NULL;
  roughtime_result_t err = ROUGHTIME_SUCCESS;

  uint8_t buf[len + context_len];
  if (context != NULL) {
    memcpy(buf, context, context_len);
  }
  memcpy(buf + context_len, data, len);

  pkey = rtfun.EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  RETURN_IF(pkey == NULL, ROUGHTIME_INTERNAL_ERROR, "EVP_PKEY_new_raw_public_key returned NULL.");
  ctx = rtfun.EVP_MD_CTX_new();
  RETURN_IF(ctx == NULL, ROUGHTIME_INTERNAL_ERROR, "EVP_MD_CTX_new returned NULL.");

  EVP_PKEY_CTX *pctx = NULL;
  RETURN_IF(rtfun.EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, pkey) != 1,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_DigestVerifyInit returned error.");
  int ret = rtfun.EVP_DigestVerify(ctx, signature, 64, buf, len + context_len);
  switch (ret) {
    case 0: err = ROUGHTIME_BAD_SIGNATURE; break;
    case 1: err = ROUGHTIME_SUCCESS;       break;
    default: RETURN_IF(true, ROUGHTIME_INTERNAL_ERROR, "EVP_DigestVerify returned error.");
  }

error:
  if (ctx != NULL) {
    EVP_MD_CTX_free(ctx);
  }
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
  return err;
}

roughtime_result_t sign(
    const uint8_t *restrict data,
    uint32_t len,
    const uint8_t *restrict context,
    uint32_t context_len,
    uint8_t *restrict signature,
    const uint8_t *restrict private_key) {

  if (data == NULL
      || len == 0
      || signature == NULL
      || private_key == NULL
      || (context == NULL && context_len > 0)) {
    if (signature != NULL) {
      memset(signature, 0, 64);
    }
    return ROUGHTIME_BAD_ARGUMENT;
  }

  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_MD_CTX *ctx = NULL;
  roughtime_result_t err = ROUGHTIME_SUCCESS;

  uint8_t buf[len + context_len];
  if (context_len > 0) {
    memcpy(buf, context, context_len);
  }
  memcpy(buf + context_len, data, len);

  pkey = rtfun.EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
  RETURN_IF(pkey == NULL, ROUGHTIME_INTERNAL_ERROR, "EVP_PKEY_new_raw_private_key returned NULL.");
  pctx = rtfun.EVP_PKEY_CTX_new(pkey, NULL);
  RETURN_IF(pctx == NULL, ROUGHTIME_INTERNAL_ERROR, "EVP_PKEY_CTX_new returned NULL.");
  EVP_PKEY_free(pkey);
  pkey = NULL;
  ctx = rtfun.EVP_MD_CTX_new();
  RETURN_IF(ctx == NULL, ROUGHTIME_INTERNAL_ERROR, "EVP_MD_CTX_new returned NULL.");
  rtfun.EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
  RETURN_IF(
      rtfun.EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_DigestSignInit returned error.");

  size_t siglen = 64;
  RETURN_IF(
      rtfun.EVP_DigestSign(ctx, signature, &siglen, buf, len + context_len) != 1,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_DigestSign returned error.");
  RETURN_IF(
      siglen != 64,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_DigestSign returned wrong signature length");

error:
  if (err != ROUGHTIME_SUCCESS) {
    memset(signature, 0, 64);
  }
  if (ctx != NULL) {
    EVP_MD_CTX_free(ctx);
  }
  if (pctx != NULL) {
    EVP_PKEY_CTX_free(pctx);
  }
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
  return err;
}

/**
 * Creates the public key associated with a private ed25519 key.
 * @param priv a 32 byte (256 bit) private ed25519 key.
 * @param publ a 32 byte array where the generated public key will be returned.
 */
roughtime_result_t priv_to_publ(const uint8_t *restrict priv, uint8_t *restrict publ) {
  EVP_PKEY *pkey = NULL;
  roughtime_result_t err = ROUGHTIME_SUCCESS;
  RETURN_IF(
      priv == NULL || publ == NULL,
      ROUGHTIME_BAD_ARGUMENT,
      "priv_to_publ called with a NULL argument.");
  pkey = rtfun.EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32);;
  RETURN_IF(
      pkey == NULL,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_PKEY_new_raw_private_key returned NULL");
  size_t keylen = 32;
  RETURN_IF(
      rtfun.EVP_PKEY_get_raw_public_key(pkey, publ, &keylen) != 1,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_PKEY_get_raw_public_key returned error.");
  RETURN_IF(
      keylen != 32,
      ROUGHTIME_INTERNAL_ERROR,
      "EVP_PKEY_get_raw_public_key returned bad keylen.");

error:
  if (err != ROUGHTIME_SUCCESS) {
    if (publ != NULL) {
      memset(publ, 0, 32);
    }
  }
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
  return err;
}

roughtime_result_t from_base64(
    const uint8_t *restrict base64,
    uint8_t *restrict out,
    size_t *restrict len_out) {
  if (base64 == NULL || out == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  size_t b64_len = strlen((char*)base64);
  uint8_t b64[b64_len + 1];
  memcpy(b64, base64, b64_len + 1);
  trim((char*)b64);
  b64_len = strlen((char*)b64);
  if ((b64_len / 4) * 3 > *len_out) {
    fprintf(stderr, "Output buffer too small.\n");
    return ROUGHTIME_BAD_ARGUMENT;
  }
  size_t len = 0;
  if ((len = rtfun.EVP_DecodeBlock(out, b64, b64_len)) < 1) {
    explicit_bzero(out, *len_out);
    fprintf(stderr, "Error when base64 decoding string.\n");
    return ROUGHTIME_INTERNAL_ERROR;
  }
  len -= b64[b64_len - 2] == '=';
  len -= b64[b64_len - 1] == '=';
  if (len > *len_out) {
    explicit_bzero(out, *len_out);
    fprintf(stderr, "Decoded base64 data size exceeded output buffer size.\n");
    return ROUGHTIME_INTERNAL_ERROR;
  }
  *len_out = len;
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t test_cert(
    const uint8_t *restrict publ,
    const uint8_t *restrict cert,
    bool verbose) {
  uint32_t offset, len;
  uint8_t *dele = NULL;
  uint8_t sig[64];
  uint8_t pubk[32];
  roughtime_result_t err = ROUGHTIME_SUCCESS;
  roughtime_header_t header;

  RETURN_ON_ERROR(rtfun.parse_roughtime_header((uint8_t*)cert, 152, &header),
      "Error when parsing CERT header.");
  RETURN_IF(header.num_tags != 2, ROUGHTIME_FORMAT_ERROR,
      "Unexpected number of tags in CERT header.");

  RETURN_ON_ERROR(rtfun.get_header_tag(&header, str_to_tag("DELE"), &offset, &len), "Missing DELE tag.");

  dele = rtfun.malloc(len);
  RETURN_IF(dele == NULL, ROUGHTIME_MEMORY_ERROR, "Malloc returned NULL.");
  memcpy(dele, cert + offset, len);

  RETURN_ON_ERROR(rtfun.get_header_tag(
      &header,
      str_to_tag("SIG"), &offset, &len),
      "Missing SIG tag.");
  RETURN_IF(len != 64, ROUGHTIME_FORMAT_ERROR, "Bad signature length.");
  memcpy(sig, cert + offset, 64);

  RETURN_ON_ERROR(
      rtfun.parse_roughtime_header(dele, 72, &header),
      "Error when parsing DELE header.");
  RETURN_IF(
      header.num_tags != 3,
      ROUGHTIME_FORMAT_ERROR,
      "Unexpected number of tags in DELE header.");

  RETURN_ON_ERROR(
      rtfun.get_header_tag(&header, str_to_tag("PUBK"), &offset, &len),
      "Missing PUBK tag.");
  RETURN_IF(len != 32, ROUGHTIME_FORMAT_ERROR, "Bad public key length.");
  memcpy(pubk, dele + offset, 32);

  RETURN_ON_ERROR(rtfun.get_header_tag(&header,
                                 str_to_tag("MINT"),
                                 &offset,
                                 &len),
                  "Missing MINT tag.");
  RETURN_IF(len != 8, ROUGHTIME_FORMAT_ERROR, "Bad MINT length.");
  uint64_t mint = le64toh(*((uint64_t*)(dele + offset)));

  RETURN_ON_ERROR(
      rtfun.get_header_tag(&header, str_to_tag("MAXT"), &offset, &len),
      "Missing MAXT tag.");
  RETURN_IF(len != 8, ROUGHTIME_FORMAT_ERROR, "Bad MAXT length.");
  uint64_t maxt = le64toh(*((uint64_t*)(dele + offset)));

  if (verbose) {
    uint32_t year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    timestamp_to_time(mint, &year, &month, &day, &hour, &minute, &second);
    printf("MINT: %" PRIu32 "-%02" PRIu32 "-%02" PRIu32 " %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32
        " (%016" PRIx64 ")\n", year, month, day, hour, minute, second, mint);
    timestamp_to_time(maxt, &year, &month, &day, &hour, &minute, &second);
    printf("MAXT: %" PRIu32 "-%02" PRIu32 "-%02" PRIu32 " %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32
        " (%016" PRIx64 ")\n", year, month, day, hour, minute, second, maxt);
  }

  err = rtfun.verify_signature(
      dele,
      72,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      sig,
      (uint8_t*)publ);
  if (verbose) {
    if (err == ROUGHTIME_SUCCESS) {
      printf("Good signature!\n");
    } else if (err == ROUGHTIME_BAD_SIGNATURE) {
      printf("BAD SIGNATURE!\n");
    } else {
      printf("Internal error when verifying signature.\n");
    }
  }
  RETURN_ON_ERROR(err, "Error when verifying signature.");

error:
  free(dele);
  return err;
}

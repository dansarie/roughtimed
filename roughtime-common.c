/* roughtime-common.c

   Copyright (C) 2019-2025 Marcus Dansarie <marcus@dansarie.se>

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

#include "roughtime-common.h"
#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

const uint32_t CERTIFICATE_CONTEXT_LEN = 34;
const uint32_t SIGNED_RESPONSE_CONTEXT_LEN = 32;
const uint8_t *const CERTIFICATE_CONTEXT = (uint8_t*)"RoughTime v1 delegation signature";
const uint8_t *const SIGNED_RESPONSE_CONTEXT = (uint8_t*)"RoughTime v1 response signature";

void trim(char *str) {
  size_t p = 0;
  while (isspace(str[p]) && str[p] != '\0') {
    p += 1;
  }
  size_t len = strlen(str) - p;
  memmove(str, str + p, len + 1);
  if (len == 0) {
    return;
  }
  for (p = len - 1; isspace(str[p]) && p >= 0; p--) {
    str[p] = '\0';
  }
}

uint32_t str_to_tag(const char *str) {
  uint32_t ret = 0;
  for (int i = 0; i < 4; i++) {
    if (str[i] == '\0') {
      return ret;
    }
    ret |= str[i] << i * 8;
  }
  return ret;
}

roughtime_result_t create_roughtime_packet(uint8_t *restrict packet, uint32_t *restrict size,
    uint32_t num_tags, ...) {

  if (packet == NULL || size == NULL || num_tags == 0) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  uint32_t *header = (uint32_t*)packet;

  if (*size < num_tags * 8) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  header[0] = htole32(num_tags);

  const uint32_t header_len = num_tags * 8;
  uint32_t offset = 0;

  va_list ap;
  va_start(ap, num_tags);

  uint32_t last_tag = 0;
  for (uint32_t i = 0; i < num_tags; i++) {
    if (i != 0) {
      header[i] = htole32(offset);
    }
    uint32_t tag = str_to_tag(va_arg(ap, char*));
    assert(tag > last_tag); /* Assertion fails if tags are not sorted. */
    last_tag = tag;
    header[num_tags + i] = htole32(tag);
    uint32_t field_size = va_arg(ap, uint32_t);
    if (field_size % 4 != 0 || header_len + offset + field_size > *size) {
      va_end(ap);
      return ROUGHTIME_BAD_ARGUMENT;
    }
    uint32_t *ptr = va_arg(ap, uint32_t*);
    assert(header_len + offset + field_size <= *size);
    memcpy(packet + header_len + offset, ptr, field_size);
    offset += field_size;
  }

  va_end(ap);
  *size = offset + header_len;
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t parse_roughtime_header(const uint8_t *restrict packet, uint32_t packet_len,
    roughtime_header_t *restrict header) {

  if (packet == NULL || packet_len < 12 || packet_len % 4 != 0 || header == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  header->num_tags = le32toh(*((uint32_t*)packet));
  uint32_t header_len = header->num_tags * 8;
  if (header->num_tags == 0 || header->num_tags * 12 > packet_len || header_len >= packet_len
      || header->num_tags > ROUGHTIME_HEADER_MAX_TAGS) {
    return ROUGHTIME_FORMAT_ERROR;
  }

  for (uint32_t i = 0; i < header->num_tags; i++) {
    if (i == 0) {
      header->offsets[i] = header_len;
    } else {
      header->offsets[i] = le32toh(((uint32_t*)packet)[i]) + header_len;
      if (header->offsets[i] % 4 != 0 || header->offsets[i] < header->offsets[i - 1]
          || header->offsets[i] > packet_len) {
        return ROUGHTIME_FORMAT_ERROR;
      }
      header->lengths[i - 1] = header->offsets[i] - header->offsets[i - 1];
    }
    header->tags[i] = le32toh(((uint32_t*)packet)[i + header->num_tags]);
    /* Check for unsorted or duplicate tags. */
    if (i > 0 && header->tags[i] <= header->tags[i - 1]) {
      return ROUGHTIME_FORMAT_ERROR;
    }
  }
  header->lengths[header->num_tags - 1] = packet_len - header->offsets[header->num_tags - 1];
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t get_header_tag(const roughtime_header_t *restrict header,
    uint32_t tag, uint32_t *restrict offset, uint32_t *restrict length) {

  if (header == NULL || offset == NULL || length == NULL
      || header->num_tags >= ROUGHTIME_HEADER_MAX_TAGS) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  for (int i = 0; i < header->num_tags; i++) {
    if (header->tags[i] == tag) {
      *offset = header->offsets[i];
      *length = header->lengths[i];
      return ROUGHTIME_SUCCESS;
    }
  }
  return ROUGHTIME_NOT_FOUND;
}

roughtime_result_t timestamp_to_time(time_t timestamp, uint32_t *restrict year,
    uint32_t *restrict month, uint32_t *restrict day, uint32_t *restrict hour,
    uint32_t *restrict minute, uint32_t *restrict second) {

  if (year == NULL || month == NULL || day == NULL || hour == NULL || minute == NULL
      || second == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  roughtime_result_t err = ROUGHTIME_SUCCESS;

  struct tm ts = {0};
  RETURN_IF(gmtime_r(&timestamp, &ts) != &ts, ROUGHTIME_INTERNAL_ERROR, "gmtime_r returned error.");
  *year   = ts.tm_year  + 1900;
  *month  = ts.tm_mon   + 1;
  *day    = ts.tm_mday;
  *hour   = ts.tm_hour;
  *minute = ts.tm_min;
  *second = ts.tm_sec;

error:
  return err;
}

roughtime_result_t verify_signature(const uint8_t *restrict data, uint32_t len,
    const uint8_t *restrict context, uint32_t context_len,
    const uint8_t *restrict signature, const uint8_t *restrict public_key) {

  if (data == NULL || len == 0 || signature == NULL || public_key == NULL
      || (context == NULL && context_len > 0)) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  uint8_t buf[len + context_len];
  if (context != NULL) {
    memcpy(buf, context, context_len);
  }
  memcpy(buf + context_len, data, len);

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL || pkey == NULL || pctx == NULL) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ROUGHTIME_INTERNAL_ERROR;
  }

  if (EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  int ret = EVP_DigestVerify(ctx, signature, 64, buf, len + context_len);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  switch (ret) {
    case 0:
      return ROUGHTIME_BAD_SIGNATURE;
    case 1:
      return ROUGHTIME_SUCCESS;
    default:
      return ROUGHTIME_INTERNAL_ERROR;
  }
}

roughtime_result_t sign(const uint8_t *restrict data, uint32_t len,
    const uint8_t *restrict context, uint32_t context_len,
    uint8_t *restrict signature, const uint8_t *restrict private_key) {

  if (data == NULL || len == 0 || signature == NULL || private_key == NULL
      || (context == NULL && context_len > 0)) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  uint8_t buf[len + context_len];
  memcpy(buf, context, context_len);
  memcpy(buf + context_len, data, len);

  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
  EVP_PKEY_free(pkey);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
  if (ctx == NULL || pkey == NULL || pctx == NULL) {
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);
    return ROUGHTIME_INTERNAL_ERROR;
  }

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  size_t siglen = 64;
  int ret = EVP_DigestSign(ctx, signature, &siglen, buf, len + context_len);
  assert(siglen == 64);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_CTX_free(pctx);
  if (ret != 1) {
    return ROUGHTIME_INTERNAL_ERROR;
  }
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t from_base64(const uint8_t *restrict base64, uint8_t *restrict out,
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
  int len = 0;
  if ((len = EVP_DecodeBlock(out, b64, b64_len)) < 1) {
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

roughtime_result_t test_cert(const uint8_t *restrict publ, const uint8_t *restrict cert,
    bool verbose) {
  uint32_t offset, len;
  uint8_t *dele = NULL;
  uint8_t sig[64];
  uint8_t pubk[32];
  roughtime_result_t err = ROUGHTIME_SUCCESS;
  roughtime_header_t header;

  RETURN_ON_ERROR(parse_roughtime_header((uint8_t*)cert, 152, &header),
      "Error when parsing CERT header.");
  RETURN_IF(header.num_tags != 2, ROUGHTIME_FORMAT_ERROR,
      "Unexpected number of tags in CERT header.");

  RETURN_ON_ERROR(get_header_tag(&header, str_to_tag("DELE"), &offset, &len), "Missing DELE tag.");

  dele = malloc(len);
  RETURN_IF(dele == NULL, ROUGHTIME_MEMORY_ERROR, "Malloc returned NULL.");
  memcpy(dele, cert + offset, len);

  RETURN_ON_ERROR(get_header_tag(&header, str_to_tag("SIG"), &offset, &len), "Missing SIG tag.");
  RETURN_IF(len != 64, ROUGHTIME_FORMAT_ERROR, "Bad signature length.");
  memcpy(sig, cert + offset, 64);

  RETURN_ON_ERROR(parse_roughtime_header(dele, 72, &header), "Error when parsing DELE header.");
  RETURN_IF(header.num_tags != 3, ROUGHTIME_FORMAT_ERROR,
      "Unexpected number of tags in DELE header.");

  RETURN_ON_ERROR(get_header_tag(&header, str_to_tag("PUBK"), &offset, &len), "Missing PUBK tag.");
  RETURN_IF(len != 32, ROUGHTIME_FORMAT_ERROR, "Bad public key length.");
  memcpy(pubk, dele + offset, 32);

  RETURN_ON_ERROR(get_header_tag(&header, str_to_tag("MINT"), &offset, &len), "Missing MINT tag.");
  RETURN_IF(len != 8, ROUGHTIME_FORMAT_ERROR, "Bad MINT length.");
  uint64_t mint = le64toh(*((uint64_t*)(dele + offset)));

  RETURN_ON_ERROR(get_header_tag(&header, str_to_tag("MAXT"), &offset, &len), "Missing MAXT tag.");
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

  err = verify_signature(dele, 72, CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT_LEN, sig,
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

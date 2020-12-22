/* roughtime-common.c
   Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se> */

#include "roughtime-common.h"
#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

const uint32_t CERTIFICATE_CONTEXT_LEN = 36;
const uint32_t SIGNED_RESPONSE_CONTEXT_LEN = 32;
const uint8_t *const CERTIFICATE_CONTEXT = (uint8_t*)"RoughTime v1 delegation signature--";
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
      if (header->offsets[i] % 4 != 0 || header->offsets[i] <= header->offsets[i - 1]
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

roughtime_result_t timestamp_to_time(uint64_t timestamp, uint32_t *restrict mjd,
    uint32_t *restrict hour, uint32_t *restrict minute, uint32_t *restrict second,
    uint32_t *restrict microsecond) {

  if (mjd == NULL || hour == NULL || minute == NULL || second == NULL || microsecond == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  *mjd = timestamp >> 40;
  timestamp &= 0xFFFFFFFFFFULL;

  if (timestamp >= 86401000000) {
    return ROUGHTIME_FORMAT_ERROR;
  } else if (timestamp >= 86400000000) {
    /* Leap second. */
    *hour = 23;
    *minute = 59;
    *second = 60;
    *microsecond = timestamp - 86400000000;
    return ROUGHTIME_SUCCESS;
  }

  *hour = timestamp / 3600000000;
  timestamp -= *hour;
  *minute = timestamp / 60000000;
  timestamp -= *minute;
  *second = timestamp / 1000000;
  timestamp -= *second;
  *microsecond = timestamp;

  return ROUGHTIME_SUCCESS;
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

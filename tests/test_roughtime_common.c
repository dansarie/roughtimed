/* test_roughtime_common.c

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

#include <check.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>

#define TEST_CODE
#include "hooks.h"
#include "../src/roughtime_common.h"

/**
 * Used to set a uint32 value in a Roughtime buffer.
 * @param B pointer to the uint32 value.
 * @param V the value to set.
 */
#define SET_UINT32(B, V) {\
  uint32_t tmp = htole32(V);\
  memcpy((B), &tmp, sizeof(uint32_t));\
}

/**
 * Used to add a value to a uint32 value in a Roughtime buffer.
 * @param B pointer to the uint32 value.
 * @param V the value to add to the existing value.
 */
#define ADD_UINT32(B, V) {\
  void *ptr = (B);\
  uint32_t tmp = 0;\
  memcpy(&tmp, ptr, sizeof(uint32_t));\
  tmp = htole32(le32toh(tmp) + (V));\
  memcpy(ptr, &tmp, sizeof(uint32_t));\
}

/* A test SREP message. */
const uint8_t g_srep_message[92] = {
  0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00,
  0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
  0x56, 0x45, 0x52, 0x00, 0x52, 0x41, 0x44, 0x49, 0x4d, 0x49,
  0x44, 0x50, 0x56, 0x45, 0x52, 0x53, 0x52, 0x4f, 0x4f, 0x54,
  0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa3, 0x4d,
  0x7b, 0x6a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
  0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
  0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
  0xcc, 0xdd
};
#define SREP_MESSAGE_LEN (92)
const uint32_t g_srep_message_len = SREP_MESSAGE_LEN;
/* Tag values in the test SREP message. Values are set by setup(). */
uint32_t g_srep_ver_value = 0;
uint32_t g_srep_radi = 0;
uint64_t g_srep_midp = 0;
const uint8_t g_srep_root[32] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
  0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
  0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
  0xcc, 0xdd
};

/* AAECAwQFBgcICQoLDA0ODxAREhMUFRYRGBkaGxwdHh8= */
const uint8_t g_private_key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x11, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
/* DsPVpqoffslYQPVstv1tekGHMS2sQ1wNsIMO+sN39vw= */
const uint8_t g_public_key[32] = {
  0x0e, 0xc3, 0xd5, 0xa6, 0xaa, 0x1f, 0x7e, 0xc9, 0x58, 0x40, 0xf5, 0x6c, 0xb6, 0xfd, 0x6d, 0x7a,
  0x41, 0x87, 0x31, 0x2d, 0xac, 0x43, 0x5c, 0x0d, 0xb0, 0x83, 0x0e, 0xfa, 0xc3, 0x77, 0xf6, 0xfc
};
const uint8_t g_expected_sig_no_ctx[64] = {
  0xac, 0x22, 0x82, 0xe0, 0x7f, 0xe0, 0x01, 0x19, 0x48, 0x58, 0x9d, 0x78, 0x41, 0xcd, 0x38, 0x57,
  0x68, 0x5b, 0x66, 0x51, 0xf7, 0x07, 0x5f, 0xc5, 0xb3, 0x57, 0x35, 0x37, 0xe2, 0x9a, 0x73, 0xc0,
  0x4d, 0xe6, 0xf9, 0x6d, 0x33, 0x42, 0xb1, 0xe6, 0x5f, 0x93, 0xb7, 0x32, 0xe1, 0xf3, 0x0e, 0xd4,
  0xc4, 0x5f, 0x40, 0xdd, 0x71, 0x52, 0x05, 0x79, 0xb3, 0x7b, 0x8b, 0xc7, 0xe0, 0xc1, 0x76, 0x07
};
const uint8_t g_expected_sig_ctx[64] = {
  0x74, 0xd9, 0x0b, 0xce, 0x88, 0x9b, 0x97, 0xe2, 0x54, 0x24, 0xfb, 0xd9, 0xd5, 0x96, 0x7d, 0xc5,
  0x33, 0x56, 0x12, 0x1d, 0xbb, 0x6f, 0x13, 0xe1, 0x2f, 0x18, 0xe0, 0x37, 0xcb, 0x45, 0x4d, 0x15,
  0xdf, 0x12, 0x01, 0x00, 0x2d, 0x3f, 0x18, 0x73, 0xbc, 0x46, 0x33, 0x8a, 0x30, 0x44, 0x0a, 0x1c,
  0xb6, 0x14, 0xd2, 0x84, 0x98, 0xdb, 0x97, 0xad, 0xa9, 0xa6, 0x99, 0x8f, 0x29, 0x9a, 0x0d, 0x05
};
const uint8_t g_zero_sig[64] = {0};

union {
  roughtime_result_t rt;
  int i;
} g_fail_return;

size_t g_fail_keylen = 32;
size_t g_fail_siglen = 64;

roughtime_result_t fail_get_header_tag(
    const roughtime_header_t *restrict header,
    uint32_t tag,
    uint32_t *restrict offset,
    uint32_t *restrict length) {
  (void)header;
  (void)tag;
  (void)offset;
  (void)length;
  return g_fail_return.rt;
}

roughtime_result_t fail_parse_roughtime_header(
    const uint8_t *restrict message,
    uint32_t message_len,
    roughtime_header_t *restrict header) {
  (void)message;
  (void)message_len;
  (void)header;
  return g_fail_return.rt;
}

roughtime_result_t fail_verify_signature(
    const uint8_t *restrict data,
    uint32_t len,
    const uint8_t *restrict context,
    uint32_t context_len,
    const uint8_t *restrict signature,
    const uint8_t *restrict public_key) {
  (void)data;
  (void)len;
  (void)context;
  (void)context_len;
  (void)signature;
  (void)public_key;
  return g_fail_return.rt;
}

void* fail_malloc(size_t size) {
  (void)size;
  return NULL;
}

struct tm* fail_gmtime_r(
    const time_t *restrict timep,
    struct tm *restrict result) {
  (void)timep;
  (void)result;
  return NULL;
}

int fail_EVP_DecodeBlock(
    unsigned char *t,
    const unsigned char *f,
    int n) {
  (void)t;
  (void)f;
  (void)n;
  return g_fail_return.i;
}

int fail_EVP_DigestSign(
    EVP_MD_CTX *ctx,
    unsigned char *sig,
    size_t *siglen,
    const unsigned char *tbs,
    size_t tbslen) {
  (void)ctx;
  (void)sig;
  (void)siglen;
  (void)tbs;
  (void)tbslen;
  *siglen = g_fail_siglen;
  return g_fail_return.i;
}

int fail_EVP_DigestSignInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey) {
  (void)ctx;
  (void)pctx;
  (void)type;
  (void)e;
  (void)pkey;
  return g_fail_return.i;
}

int fail_EVP_DigestVerify(
    EVP_MD_CTX *ctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen) {
  (void)ctx;
  (void)sig;
  (void)siglen;
  (void)tbs;
  (void)tbslen;
  return g_fail_return.i;
}

int fail_EVP_DigestVerifyInit(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX **pctx,
    const EVP_MD *type,
    ENGINE *e,
    EVP_PKEY *pkey) {
  (void)ctx;
  (void)pctx;
  (void)type;
  (void)e;
  (void)pkey;
  return g_fail_return.i;
}

EVP_MD_CTX* fail_EVP_MD_CTX_new(void) {
  return NULL;
}

void fail_EVP_MD_CTX_set_pkey_ctx(
    EVP_MD_CTX *ctx,
    EVP_PKEY_CTX *pctx) {
  (void)ctx;
  (void)pctx;
}

EVP_PKEY_CTX* fail_EVP_PKEY_CTX_new(
    EVP_PKEY *pkey,
    ENGINE *e) {
  (void)pkey;
  (void)e;
  return NULL;
}

int fail_EVP_PKEY_get_raw_public_key(
    const EVP_PKEY *pkey,
    unsigned char *pub,
    size_t *len) {
  (void)pkey;
  (void)pub;
  *len = g_fail_keylen;
  return g_fail_return.i;
}

EVP_PKEY* fail_EVP_PKEY_new_raw_private_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen) {
  (void)type;
  (void)e;
  (void)key;
  (void)keylen;
  return NULL;
}

EVP_PKEY* fail_EVP_PKEY_new_raw_public_key(
    int type,
    ENGINE *e,
    const unsigned char *key,
    size_t keylen) {
  (void)type;
  (void)e;
  (void)key;
  (void)keylen;
  return NULL;
}

void test_trim_str(const char *in, const char *out) {
  char str[1000] = {0};
  ck_assert(strlen(in) < 1000);
  strcpy(str, in);
  trim(str);
  ck_assert_str_eq(str, out);
}

START_TEST(test_trim) {
  test_trim_str("",   "");
  test_trim_str(" ",  "");
  test_trim_str("  ", "");
  test_trim_str(" a ", "a");
  test_trim_str("  a ", "a");
  test_trim_str(" a  ", "a");
  test_trim_str("a", "a");
  test_trim_str("a b", "a b");
  test_trim_str(" a b ", "a b");
}
END_TEST

START_TEST(test_str_to_tag) {
  ck_assert_uint_eq(str_to_tag(NULL), 0);
  ck_assert_uint_eq(str_to_tag("SIG"), 0x00474953);
  ck_assert_uint_eq(str_to_tag("NONC"), 0x434e4f4e);
  ck_assert_uint_eq(str_to_tag("NONCe"), 0x434e4f4e);
}
END_TEST

START_TEST(test_create_roughtime_message) {
  uint32_t buf_len = 200;
  uint8_t buf[200] = {0};

  /* A correct call. */
  roughtime_result_t res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(buf_len, g_srep_message_len);
  ck_assert_mem_eq(buf, g_srep_message, g_srep_message_len);

  /* A correct call with the exact required buffer size. */
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(buf_len, g_srep_message_len);
  ck_assert_mem_eq(buf, g_srep_message, g_srep_message_len);

  /* Calls with bad arguments. */
  buf_len = 200;
  res = create_roughtime_message(
      NULL,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  buf_len = 200;
  res = create_roughtime_message(
      buf,
      NULL,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  buf_len = 200;
  res = create_roughtime_message(buf, &buf_len, 0);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Call with buffer smaller than required header size. */
  buf_len = 39;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Calls with unsorted tags. */
  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "RADI", 4, &g_srep_radi,
      "VER",  4, &g_srep_ver_value,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "ROOT", 32, g_srep_root,
      "VERS", 4, &g_srep_ver_value);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Call with bad field size. */
  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  5, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Call with too small buffer size. */
  buf_len = 91;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &g_srep_ver_value,
      "RADI", 4, &g_srep_radi,
      "MIDP", 8, &g_srep_midp,
      "VERS", 4, &g_srep_ver_value,
      "ROOT", 32, g_srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);
}
END_TEST

START_TEST(test_parse_roughtime_header) {
  roughtime_header_t header = {0};
  roughtime_result_t res = ROUGHTIME_SUCCESS;

  uint8_t badmsg[(ROUGHTIME_HEADER_MAX_TAGS + 1) * 8 + 1]= {0};

  /* Test a few bad calls. */
  res = parse_roughtime_header(NULL, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(g_srep_message, 0, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(g_srep_message, g_srep_message_len - 1, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(g_srep_message, g_srep_message_len + 1, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(g_srep_message, g_srep_message_len, NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  /* Test message with zero tags. */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  SET_UINT32(badmsg, 0);
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with 12 tags, requiring 96 bytes, which is more than srep_message_len. */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  SET_UINT32(badmsg, 12);
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with more than ROUGHTIME_HEADER_MAX_TAGS. . */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  SET_UINT32(badmsg, ROUGHTIME_HEADER_MAX_TAGS + 1);
  res = parse_roughtime_header(badmsg, (ROUGHTIME_HEADER_MAX_TAGS + 1) * 8, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test messages with bad offset values. */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  ADD_UINT32(badmsg + sizeof(uint32_t), 1);
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  memcpy(badmsg, g_srep_message, g_srep_message_len);
  SET_UINT32(badmsg + 3 * sizeof(uint32_t), 0);
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  memcpy(badmsg, g_srep_message, g_srep_message_len);
  ADD_UINT32(badmsg + 4 * sizeof(uint32_t), g_srep_message_len + 4);
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with duplicate tag. */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  memcpy(badmsg + 5 * sizeof(uint32_t), badmsg + 6 * sizeof(uint32_t), sizeof(uint32_t));
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with out-of-order tag. */
  memcpy(badmsg, g_srep_message, g_srep_message_len);
  uint32_t tmp = 0;
  memcpy(&tmp, badmsg + 7 * sizeof(uint32_t), sizeof(uint32_t));
  memcpy(badmsg + 7 * sizeof(uint32_t), badmsg + 5 * sizeof(uint32_t), sizeof(uint32_t));
  memcpy(badmsg + 5 * sizeof(uint32_t), &tmp, sizeof(uint32_t));
  res = parse_roughtime_header(badmsg, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test correct call. */
  res = parse_roughtime_header(g_srep_message, g_srep_message_len, &header);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(header.num_tags, 5);
  ck_assert_uint_eq(header.offsets[0], 40);
  ck_assert_uint_eq(header.offsets[1], 44);
  ck_assert_uint_eq(header.offsets[2], 48);
  ck_assert_uint_eq(header.offsets[3], 56);
  ck_assert_uint_eq(header.offsets[4], 60);
  ck_assert_uint_eq(header.lengths[0], 4);
  ck_assert_uint_eq(header.lengths[1], 4);
  ck_assert_uint_eq(header.lengths[2], 8);
  ck_assert_uint_eq(header.lengths[3], 4);
  ck_assert_uint_eq(header.lengths[4], 32);
  ck_assert_uint_eq(header.tags[0], str_to_tag("VER"));
  ck_assert_uint_eq(header.tags[1], str_to_tag("RADI"));
  ck_assert_uint_eq(header.tags[2], str_to_tag("MIDP"));
  ck_assert_uint_eq(header.tags[3], str_to_tag("VERS"));
  ck_assert_uint_eq(header.tags[4], str_to_tag("ROOT"));

  /* Test correct calls to get_header_tag. */
  uint32_t offset = 0;
  uint32_t length = 0;
  res = get_header_tag(&header, str_to_tag("VER"), &offset, &length);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(offset, 40);
  ck_assert_uint_eq(length, 4);

  offset = 0;
  length = 0;
  res = get_header_tag(&header, str_to_tag("RADI"), &offset, &length);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(offset, 44);
  ck_assert_uint_eq(length, 4);

  offset = 0;
  length = 0;
  res = get_header_tag(&header, str_to_tag("MIDP"), &offset, &length);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(offset, 48);
  ck_assert_uint_eq(length, 8);

  offset = 0;
  length = 0;
  res = get_header_tag(&header, str_to_tag("VERS"), &offset, &length);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(offset, 56);
  ck_assert_uint_eq(length, 4);

  offset = 0;
  length = 0;
  res = get_header_tag(&header, str_to_tag("ROOT"), &offset, &length);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(offset, 60);
  ck_assert_uint_eq(length, 32);

  /* Test getting a tag not in the struct. */
  offset = 123;
  length = 456;
  res = get_header_tag(&header, str_to_tag("NONC"), &offset, &length);
  ck_assert(res == ROUGHTIME_NOT_FOUND);
  ck_assert_uint_eq(offset, 0);
  ck_assert_uint_eq(length, 0);

  /* Test bad calls to get_header_tag. */
  offset = 123;
  length = 456;
  res = get_header_tag(NULL, str_to_tag("RADI"), &offset, &length);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(offset, 0);
  ck_assert_uint_eq(length, 0);

  offset = 123;
  length = 456;
  res = get_header_tag(&header, str_to_tag("RADI"), NULL, &length);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(length, 0);

  offset = 123;
  length = 456;
  res = get_header_tag(&header, str_to_tag("RADI"), &offset, NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(offset, 0);


  offset = 123;
  length = 456;
  header.num_tags = ROUGHTIME_HEADER_MAX_TAGS + 1;
  res = get_header_tag(&header, str_to_tag("RADI"), &offset, &length);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(offset, 0);
  ck_assert_uint_eq(length, 0);
}
END_TEST

START_TEST(test_timestamp_to_time) {
  uint32_t year = 0;
  uint32_t month = 0;
  uint32_t day = 0;
  uint32_t hour = 1;
  uint32_t minute = 1;
  uint32_t second = 1;

  roughtime_result_t res = ROUGHTIME_SUCCESS;

  /* Test bad calls. */
  res = timestamp_to_time(0, NULL,  &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);
  ck_assert_uint_eq(second, 0);
  res = timestamp_to_time(0, &year, NULL,   &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);
  ck_assert_uint_eq(second, 0);
  res = timestamp_to_time(0, &year, &month, NULL, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);
  ck_assert_uint_eq(second, 0);
  res = timestamp_to_time(0, &year, &month, &day, NULL,  &minute, &second);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(minute, 0);
  ck_assert_uint_eq(second, 0);
  res = timestamp_to_time(0, &year, &month, &day, &hour, NULL,    &second);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(second, 0);
  res = timestamp_to_time(0, &year, &month, &day, &hour, &minute, NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);

  /* Test good calls. */
  res = timestamp_to_time(0, &year, &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(year, 1970);
  ck_assert_uint_eq(month, 1);
  ck_assert_uint_eq(day, 1);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);
  ck_assert_uint_eq(second, 0);

  res = timestamp_to_time(1786465699, &year, &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(year, 2026);
  ck_assert_uint_eq(month, 8);
  ck_assert_uint_eq(day, 11);
  ck_assert_uint_eq(hour, 16);
  ck_assert_uint_eq(minute, 28);
  ck_assert_uint_eq(second, 19);

  /* Test failure in gmtime_r. */
  rtfun.gmtime_r = fail_gmtime_r;
  res = timestamp_to_time(1786465699, &year, &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_uint_eq(year, 0);
  ck_assert_uint_eq(month, 0);
  ck_assert_uint_eq(day, 0);
  ck_assert_uint_eq(hour, 0);
  ck_assert_uint_eq(minute, 0);
  rtfun_reset();
}
END_TEST

START_TEST(test_verify_signature) {
  roughtime_result_t res = ROUGHTIME_SUCCESS;

  /* Test a few bad calls. */
  res = verify_signature(
      NULL,
      g_srep_message_len,
      NULL,
      0,
      g_expected_sig_no_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = verify_signature(
      g_srep_message,
      0,
      NULL,
      0,
      g_expected_sig_no_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      NULL,
      0,
      NULL,
      g_public_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      NULL,
      0,
      g_expected_sig_no_ctx,
      NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      NULL,
      1,
      g_expected_sig_no_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  /* Test a good call without context. */
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      NULL,
      0,
      g_expected_sig_no_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_SUCCESS);

  /* Test a good call with context. */
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_expected_sig_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_SUCCESS);

  /* Test a good call with a bad signature. */
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_zero_sig,
      g_public_key);
  ck_assert(res == ROUGHTIME_BAD_SIGNATURE);

  /* Test with simulated internal errors. */
  rtfun.EVP_PKEY_new_raw_public_key = fail_EVP_PKEY_new_raw_public_key;
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_expected_sig_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  rtfun_reset();

  rtfun.EVP_MD_CTX_new = fail_EVP_MD_CTX_new;
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_expected_sig_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  rtfun_reset();

  rtfun.EVP_DigestVerifyInit = fail_EVP_DigestVerifyInit;
  g_fail_return.i = 0;
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_expected_sig_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  rtfun_reset();

  rtfun.EVP_DigestVerify = fail_EVP_DigestVerify;
  g_fail_return.i = 2;
  res = verify_signature(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      g_expected_sig_ctx,
      g_public_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  rtfun_reset();
}

START_TEST(test_sign) {
  uint8_t signature[64] = {0};
  roughtime_result_t res = ROUGHTIME_SUCCESS;

  /* Test a few bad calls. */
  memset(signature, 0xff, 64);
  res = sign(
      NULL,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, g_zero_sig, 64);

  memset(signature, 0xff, 64);
  res = sign(
      g_srep_message,
      0,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, g_zero_sig, 64);

  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      NULL,
      g_private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  memset(signature, 0xff, 64);
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, g_zero_sig, 64);

  memset(signature, 0xff, 64);
  res = sign(
      g_srep_message,
      g_srep_message_len,
      NULL,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, g_zero_sig, 64);

  /* Test without a context string. */
  res = sign(
      g_srep_message,
      g_srep_message_len,
      NULL,
      0,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, g_expected_sig_no_ctx, 64);

  /* Test with zero-length context string. */
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      0,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, g_expected_sig_no_ctx, 64);

  /* Test with context string. */
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, g_expected_sig_ctx, 64);

  /* Test with simulated internal errors. */
  rtfun.EVP_PKEY_new_raw_private_key = fail_EVP_PKEY_new_raw_private_key;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();

  rtfun.EVP_PKEY_CTX_new = fail_EVP_PKEY_CTX_new;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();

  rtfun.EVP_MD_CTX_new = fail_EVP_MD_CTX_new;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();

  rtfun.EVP_DigestSignInit = fail_EVP_DigestSignInit;
  g_fail_return.i = 0;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();

  rtfun.EVP_DigestSign = fail_EVP_DigestSign;
  g_fail_return.i = 0;
  g_fail_siglen = 64;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();

  /* Test with simulated bad siglen return value from EVP_DigestSign. */
  rtfun.EVP_DigestSign = fail_EVP_DigestSign;
  g_fail_return.i = 1;
  g_fail_siglen = 65;
  res = sign(
      g_srep_message,
      g_srep_message_len,
      CERTIFICATE_CONTEXT,
      CERTIFICATE_CONTEXT_LEN,
      signature,
      g_private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, g_zero_sig, 64);
  rtfun_reset();
}
END_TEST

START_TEST(test_priv_to_publ) {
  roughtime_result_t res = ROUGHTIME_SUCCESS;
  uint8_t pubkey[32] = {0};

  /* Test with good values. */
  res = priv_to_publ(g_private_key, pubkey);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(pubkey, g_public_key, 32);

  /* Test with NULL arguments. */
  res = priv_to_publ(NULL, pubkey);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(pubkey, g_zero_sig, 32);

  res = priv_to_publ(g_private_key, NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(pubkey, g_zero_sig, 32);

  /* Test with simulated internal errors. */
  rtfun.EVP_PKEY_new_raw_private_key = fail_EVP_PKEY_new_raw_private_key;
  res = priv_to_publ(g_private_key, pubkey);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(pubkey, g_zero_sig, 32);
  rtfun_reset();

  rtfun.EVP_PKEY_get_raw_public_key = fail_EVP_PKEY_get_raw_public_key;
  g_fail_return.i = 0;
  g_fail_keylen = 32;
  res = priv_to_publ(g_private_key, pubkey);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(pubkey, g_zero_sig, 32);
  rtfun_reset();

  /* This should return ROUGHTIME_SUCCESS if the loop ran through all failing calls. */
  res = priv_to_publ(g_private_key, pubkey);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(pubkey, g_public_key, 32);

  /* Test with simulated bad len return value from EVP_PKEY_get_raw_public_key. */
  rtfun.EVP_PKEY_get_raw_public_key = fail_EVP_PKEY_get_raw_public_key;
  g_fail_return.i = 1;
  g_fail_keylen = 33;
  res = priv_to_publ(g_private_key, pubkey);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(pubkey, g_zero_sig, 32);
  rtfun_reset();
}
END_TEST

START_TEST(test_from_base64) {
  const char *out[]  = {
    "f",
    "fo",
    "foo",
    "foob",
    "fooba",
    "foobar"
  };
  const char *b64[] = {
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy"
  };
  size_t len_out = 0;
  char outbuf[100] = {0};
  const char zero[100] = {0};

  roughtime_result_t res = ROUGHTIME_SUCCESS;

  /* Test with good values. */
  for (int i = 0; i < 6; i++) {
    len_out = 100;
    res = from_base64((const uint8_t*)b64[i], (uint8_t*)outbuf, &len_out);
    ck_assert(res == ROUGHTIME_SUCCESS);
    ck_assert_uint_eq(len_out, strlen(out[i]));
    ck_assert_mem_eq(outbuf, out[i], strlen(out[i]));
  }

  /* Test with NULL values. */
  len_out = 100;
  res = from_base64(NULL, (uint8_t*)outbuf, &len_out);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  len_out = 100;
  res = from_base64((const uint8_t*)b64[1], NULL, &len_out);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  /* Test with too small output buffer. */
  for (int i = 3; i < 6; i++) {
    len_out = 5;
    res = from_base64((const uint8_t*)b64[i], (uint8_t*)outbuf, &len_out);
    ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  }

  /* Test with empty string. */
  len_out = 100;
  memset(outbuf, 0xff, 100);
  res = from_base64((const uint8_t*)"", (uint8_t*)outbuf, &len_out);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(outbuf, zero, 100);

  rtfun.EVP_DecodeBlock = fail_EVP_DecodeBlock;
  g_fail_return.i = 101;
  memset(outbuf, 0xff, 100);
  len_out = 100;
  res = from_base64((const uint8_t*)b64[5], (uint8_t*)outbuf, &len_out);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(outbuf, zero, 100);
  rtfun_reset();
}
END_TEST

START_TEST(test_test_cert) {
  /* Long-term private key: g_private_key
   * Long-term public key:  g_public_key
   * Delegate private key: 6Gwrs81HN2rCHPNlnfVeHOnBrYqY8mkDY2VHkGMYnak=
   */
   const char *cert = "AgAAAEAAAABTSUcAREVMRbYlPnDDM2Fm06I16Fs1JKPPPz5/+sjQnQva/GQ8qGIXzasCAC"
                      "6Bq8Tndo8mLVi+2TUpa3MPA05Gq8aEdcm8eQ4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFQY"
                      "d5ofF3ek3y8Q6FHWhW+5I/vC8UkNcS/JQPS7F4Vc0QA7PUsAAAAAgNjbcAAAAAA=";
   uint8_t certdata[200] = {0};
   size_t certlen = 200;
   roughtime_result_t res = ROUGHTIME_SUCCESS;
   res = from_base64((const uint8_t*)cert, certdata, &certlen);
   ck_assert(res == ROUGHTIME_SUCCESS);
   ck_assert_uint_eq(certlen, 152);

   res = test_cert(g_public_key, certdata, true);
   ck_assert(res == ROUGHTIME_SUCCESS);
   res = test_cert(g_public_key, certdata, false);
   ck_assert(res == ROUGHTIME_SUCCESS);

   /* Flip a bit in the certificate. */
   certdata[60] ^= 1;
   res = test_cert(g_public_key, certdata, true);
   ck_assert(res == ROUGHTIME_BAD_SIGNATURE);
   res = test_cert(g_public_key, certdata, false);
   ck_assert(res == ROUGHTIME_BAD_SIGNATURE);

   rtfun.parse_roughtime_header = fail_parse_roughtime_header;
   g_fail_return.rt = ROUGHTIME_INTERNAL_ERROR;
   res = test_cert(g_public_key, certdata, false);
   ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
   rtfun_reset();

   rtfun.malloc = fail_malloc;
   res = test_cert(g_public_key, certdata, false);
   ck_assert(res == ROUGHTIME_MEMORY_ERROR);
   rtfun_reset();

   rtfun.verify_signature = fail_verify_signature;
   g_fail_return.rt = ROUGHTIME_INTERNAL_ERROR;
   res = test_cert(g_public_key, certdata, true);
   ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
   rtfun_reset();
}
END_TEST

/**
 * Set up the test fixture by converting global variables to little endian.
 */
static void setup(void) {
  g_srep_ver_value = htole32(1);
  g_srep_radi = htole32(1);
  g_srep_midp = htole64(1786465699);
  rtfun_reset();
}

static void teardown(void) {
}

void test_roughtime_common_add(Suite *s) {
  TCase *tc = tcase_create("Common");
  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_add_test(tc, test_trim);
  tcase_add_test(tc, test_str_to_tag);
  tcase_add_test(tc, test_create_roughtime_message);
  tcase_add_test(tc, test_parse_roughtime_header);
  tcase_add_test(tc, test_timestamp_to_time);
  tcase_add_test(tc, test_verify_signature);
  tcase_add_test(tc, test_sign);
  tcase_add_test(tc, test_priv_to_publ);
  tcase_add_test(tc, test_from_base64);
  tcase_add_test(tc, test_test_cert);
  suite_add_tcase(s, tc);
}

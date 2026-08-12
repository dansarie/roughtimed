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

/* A test SREP message. */
const uint8_t srep_message[92] = {
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
const uint32_t srep_message_len = SREP_MESSAGE_LEN;
/* Tag values in the test SREP message. */
uint32_t srep_ver_value = 1;
uint32_t srep_radi = 1;
uint64_t srep_midp = 1786465699;
const uint8_t srep_root[32] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
  0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
  0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
  0xcc, 0xdd
};

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
  test_trim_str("a", "a");
}
END_TEST

START_TEST(test_str_to_tag) {
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
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_uint_eq(buf_len, srep_message_len);
  ck_assert_mem_eq(buf, srep_message, srep_message_len);

  /* Calls with bad arguments. */
  buf_len = 200;
  res = create_roughtime_message(
      NULL,
      &buf_len,
      5,
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  buf_len = 200;
  res = create_roughtime_message(
      buf,
      NULL,
      5,
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
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
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Calls with unsorted tags. */
  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "RADI", 4, &srep_radi,
      "VER",  4, &srep_ver_value,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "ROOT", 32, srep_root,
      "VERS", 4, &srep_ver_value);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Call with bad field size. */
  buf_len = 200;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  5, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);

  /* Call with too small buffer size. */
  buf_len = 91;
  res = create_roughtime_message(
      buf,
      &buf_len,
      5,
      "VER",  4, &srep_ver_value,
      "RADI", 4, &srep_radi,
      "MIDP", 8, &srep_midp,
      "VERS", 4, &srep_ver_value,
      "ROOT", 32, srep_root);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_uint_eq(buf_len, 0);
}
END_TEST

START_TEST(test_parse_roughtime_header) {
  roughtime_header_t header = {0};
  roughtime_result_t res = ROUGHTIME_SUCCESS;

  uint8_t badmsg[(ROUGHTIME_HEADER_MAX_TAGS + 1) * 8 + 1]= {0};

  /* Test a few bad calls. */
  res = parse_roughtime_header(NULL, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(srep_message, 0, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(srep_message, srep_message_len - 1, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(srep_message, srep_message_len + 1, &header);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  res = parse_roughtime_header(srep_message, srep_message_len, NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  /* Test message with zero tags. */
  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[0] = htole32(0);
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with 12 tags, requiring 96 bytes, which is more than srep_message_len. */
  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[0] = htole32(12);
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with more than ROUGHTIME_HEADER_MAX_TAGS. . */
  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[0] = htole32(ROUGHTIME_HEADER_MAX_TAGS + 1);
  res = parse_roughtime_header(badmsg, (ROUGHTIME_HEADER_MAX_TAGS + 1) * 8, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test messages with bad offset values. */
  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[1] += 1;
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[3] = 0;
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[4] += srep_message_len + 4;
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with duplicate tag. */
  memcpy(badmsg, srep_message, srep_message_len);
  ((uint32_t*)badmsg)[5] = ((uint32_t*)badmsg)[6];
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test message with out-of-order tag. */
  memcpy(badmsg, srep_message, srep_message_len);
  uint32_t tmp = ((uint32_t*)badmsg)[7];
  ((uint32_t*)badmsg)[7] = ((uint32_t*)badmsg)[5];
  ((uint32_t*)badmsg)[5] = tmp;
  res = parse_roughtime_header(badmsg, srep_message_len, &header);
  ck_assert(res == ROUGHTIME_FORMAT_ERROR);

  /* Test correct call. */
  res = parse_roughtime_header(srep_message, srep_message_len, &header);
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
  fail_gmtime_r(1, NULL);
  res = timestamp_to_time(1786465699, &year, &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
}
END_TEST

START_TEST(test_sign) {
  const uint8_t *context_str = (uint8_t*)"Test signature";
  uint8_t signature[64] = {0};
  const uint8_t private_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x11, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  const uint8_t expected_sig_no_ctx[64] = {
    0xac, 0x22, 0x82, 0xe0, 0x7f, 0xe0, 0x01, 0x19, 0x48, 0x58, 0x9d, 0x78, 0x41, 0xcd, 0x38, 0x57,
    0x68, 0x5b, 0x66, 0x51, 0xf7, 0x07, 0x5f, 0xc5, 0xb3, 0x57, 0x35, 0x37, 0xe2, 0x9a, 0x73, 0xc0,
    0x4d, 0xe6, 0xf9, 0x6d, 0x33, 0x42, 0xb1, 0xe6, 0x5f, 0x93, 0xb7, 0x32, 0xe1, 0xf3, 0x0e, 0xd4,
    0xc4, 0x5f, 0x40, 0xdd, 0x71, 0x52, 0x05, 0x79, 0xb3, 0x7b, 0x8b, 0xc7, 0xe0, 0xc1, 0x76, 0x07
  };
  const uint8_t expected_sig_ctx[64] = {
    0xce, 0x38, 0x1d, 0xfd, 0xd1, 0xb0, 0x57, 0x26, 0xa4, 0x98, 0x6e, 0xa9, 0x0d, 0x20, 0xf6, 0xd4,
    0x6d, 0x75, 0xd3, 0x99, 0x2c, 0xf2, 0xe7, 0xe1, 0xe7, 0x6a, 0xe5, 0x56, 0x3b, 0x64, 0xbd, 0x0a,
    0x30, 0x0a, 0x7e, 0xd1, 0xd6, 0xe9, 0xd9, 0xf2, 0xd1, 0xd3, 0x05, 0xde, 0xf0, 0x34, 0xdf, 0x63,
    0xb2, 0x39, 0x1a, 0x71, 0xfc, 0x16, 0xdd, 0x46, 0x88, 0x4a, 0xd7, 0xcd, 0xab, 0x69, 0xad, 0x07
  };
  const uint8_t zero_sig[64] = {0};
  roughtime_result_t res = ROUGHTIME_SUCCESS;

  /* Test a few bad calls. */
  memset(signature, 0xff, 64);
  res = sign(
      NULL,
      srep_message_len,
      context_str,
      strlen((const char*)context_str) + 1,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, zero_sig, 64);

  memset(signature, 0xff, 64);
  res = sign(
      srep_message,
      0,
      context_str,
      strlen((const char*)context_str) + 1,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, zero_sig, 64);

  res = sign(
      srep_message,
      srep_message_len,
      context_str,
      strlen((const char*)context_str) + 1,
      NULL,
      private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);

  memset(signature, 0xff, 64);
  res = sign(
      srep_message,
      srep_message_len,
      context_str,
      strlen((const char*)context_str) + 1,
      signature,
      NULL);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, zero_sig, 64);

  memset(signature, 0xff, 64);
  res = sign(
      srep_message,
      srep_message_len,
      NULL,
      strlen((const char*)context_str) + 1,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_mem_eq(signature, zero_sig, 64);

  /* Test without a context string. */
  res = sign(
      srep_message,
      srep_message_len,
      NULL,
      0,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, expected_sig_no_ctx, 64);

  /* Test with zero-length context string. */
  res = sign(
      srep_message,
      srep_message_len,
      context_str,
      0,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, expected_sig_no_ctx, 64);

  /* Test with context string. */
  res = sign(
      srep_message,
      srep_message_len,
      context_str,
      strlen((const char*)context_str) + 1,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_SUCCESS);
  ck_assert_mem_eq(signature, expected_sig_ctx, 64);

  /* Test with simulated internal errors. */
  fail_EVP_PKEY_new_raw_private_key(1, NULL);
  fail_EVP_PKEY_CTX_new(1, NULL);
  fail_EVP_MD_CTX_new(1, NULL);
  fail_EVP_DigestSignInit(1, 0);
  fail_EVP_DigestSign(1, 0);
  do {
    res = sign(
        srep_message,
        srep_message_len,
        context_str,
        strlen((const char*)context_str) + 1,
        signature,
        private_key);
    if (res == ROUGHTIME_INTERNAL_ERROR) {
      ck_assert_mem_eq(signature, zero_sig, 64);
    }
  } while (res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert(res == ROUGHTIME_SUCCESS);

  /* Test with simulated bad siglen return value from EVP_DigestSign. */
  fail_EVP_DigestSign(1, 1);
  res = sign(
      srep_message,
      srep_message_len,
      context_str,
      strlen((const char*)context_str) + 1,
      signature,
      private_key);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
  ck_assert_mem_eq(signature, zero_sig, 64);
}
END_TEST

/**
 * Set up the test fixture by converting global variables to little endian.
 */
static void setup(void) {
  srep_ver_value = htole32(srep_ver_value);
  srep_radi = htole32(srep_radi);
  srep_midp = htole64(srep_midp);

  fail_gmtime_r(-1, NULL);
  fail_EVP_PKEY_new_raw_private_key(-1, NULL);
  fail_EVP_PKEY_CTX_new(-1, NULL);
  fail_EVP_MD_CTX_new(-1, NULL);
  fail_EVP_DigestSignInit(-1, 0);
  fail_EVP_DigestSign(-1, 0);
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
  tcase_add_test(tc, test_sign);
  suite_add_tcase(s, tc);
}

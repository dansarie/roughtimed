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

#undef TESTING
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

  fail_gmtime_r(-1);

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
  fail_gmtime_r(1);
  res = timestamp_to_time(1786465699, &year, &month, &day, &hour, &minute, &second);
  ck_assert(res == ROUGHTIME_INTERNAL_ERROR);
}
END_TEST


/**
 * Set up the test fixture by converting global variables to little endian.
 */
static void setup(void) {
  srep_ver_value = htole32(srep_ver_value);
  srep_radi = htole32(srep_radi);
  srep_midp = htole64(srep_midp);
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
  suite_add_tcase(s, tc);
}

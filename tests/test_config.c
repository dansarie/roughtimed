/* test_config.c

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/config.h"

/* Dummy configuration values. */
#define CERT  "AgAAAEgAAABERUxFU0lHAAMAAAAgAAAAKAAAAFBVQktNSU5UTUFYVMx+bDE5Qw62cL/9ATw34f8OsRoN1bzgZUls4kKfWWIFAAAAAADGygAAAAAAAMfKAA/DIAxK32mZZwEwC31x4SSinH1SoLVYfrLH1IvshDjwnViJ2ty7gh5eucxk3x6OxgZmysEVup6/6FhUJ3BuVgU="
#define PRIV  "QB07lceIqGf+qh009xrYFDxh0swGH2BzIUukKhUjkNg="
#define PUBL  "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
#define STATS "/var/log/roughtime/stats.log"
/* 999 characters long. */
#define LONGSTR "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZab"\
                "cdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCD"\
                "EFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"\
                "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGH"\
                "IJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\
                "klmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"\
                "MNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"\
                "opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"\
                "QRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"\
                "stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST"\
                "UVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"\
                "wxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"\
                "YZabcdefghijklmnopqrstuvwxyzABCDEFGHIJK"

char g_tmpname[30] = {0}; /**< Name of temporary configuration file. */
char *g_buf = NULL;       /**< Buffer for building configuration file. */

/**
 * Sets the text of the temporary configuration file. The file will be truncated to zero length and
 * its contents replaced.
 * @param text the new contents of the configuration file.
 */
void set_conf_text(const char *text) {
  ck_assert_ptr_nonnull(text);
  FILE *fp = fopen(g_tmpname, "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", text);
  ck_assert(fclose(fp) == 0);
}

START_TEST(test_config) {
  /* Build the contents of the configuration file. */
  g_buf[0] = '\0';
  strcat(g_buf, "# foo bar \n");
  strcat(g_buf, "\n");
  strcat(g_buf, "  \n");
  strcat(g_buf, "cert " CERT "\n");
  strcat(g_buf, "cert some_other_value\n");
  strcat(g_buf, " priv " PRIV "\n");
  strcat(g_buf, "publ  " PUBL "\n");
  strcat(g_buf, " stats   " STATS "  \n");
  strcat(g_buf, LONGSTR " longstrkey\n");
  strcat(g_buf, "longstrval " LONGSTR "\n");
  strcat(g_buf, LONGSTR "X toolongstrkey\n");
  strcat(g_buf, "toolongstrval " LONGSTR "X\n");
  strcat(g_buf, " # bar baz  \n");
  /* Fill the file with enough key-value pairs to hit the limit of 100 pairs. */
  char filler_key[] = "aa";
  for (int i = 0; i < 94; i++) {
    filler_key[1] = 'a' + i % 10;
    filler_key[0] = 'a' + (i / 10) % 10;
    sprintf(g_buf + strlen(g_buf), "key%s value%s\n", filler_key, filler_key);
  }
  set_conf_text(g_buf);

  /* Test reading bad file names. */
  ck_assert(read_config_file(NULL) == ROUGHTIME_BAD_ARGUMENT);
  ck_assert(read_config_file("") == ROUGHTIME_FILE_ERROR);
  /* Load the configuration file. */
  ck_assert(read_config_file(g_tmpname) == ROUGHTIME_SUCCESS);
  const char *value = NULL;
  /* Test a few bad calls to get_config. */
  ck_assert(get_config("cert", NULL) == ROUGHTIME_BAD_ARGUMENT);
  ck_assert(get_config(NULL, &value) == ROUGHTIME_BAD_ARGUMENT);
  ck_assert_ptr_null(value);
  ck_assert(get_config(NULL, NULL) == ROUGHTIME_BAD_ARGUMENT);
  ck_assert(get_config("foo", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("bar", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  /* Check that we can get the contents of the configuration file. */
  ck_assert(get_config("cert", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, CERT);
  ck_assert(get_config("priv", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, PRIV);
  ck_assert(get_config("publ", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, PUBL);
  ck_assert(get_config("stats", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, STATS);
  ck_assert(get_config(LONGSTR, &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, "longstrkey");
  ck_assert(get_config("longstrval", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, LONGSTR);
  /* Check that we can't get the contents of the keys/values that exceeded maximum lenghth. */
  ck_assert(get_config(LONGSTR "X", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("toolongstrval", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  /* Check that we can not get keys added when the buffer was full. (index 100). */
  char last_key[] = "keyaa";
  last_key[3] = filler_key[0];
  last_key[4] = filler_key[1];
  ck_assert(get_config(last_key, &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  /* Check that we can get the last correctly added key (index 99). */
  last_key[4] -= 1;
  ck_assert(get_config(last_key, &value) == ROUGHTIME_SUCCESS);
  char last_value[] = "valueaa";
  last_value[5] = last_key[3];
  last_value[6] = last_key[4];
  ck_assert_str_eq(value, last_value);

  /* Check that all keys are removed when we clear the configuration. */
  clear_config();
  ck_assert(get_config("cert", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("priv", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("publ", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
  ck_assert(get_config("stats", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);

  /* Set up a new test configuration file. */
  g_buf[0] = '\0';
  strcat(g_buf, "# foo bar \n");
  strcat(g_buf, "cert " CERT "\n");
  strcat(g_buf, "priv " PRIV "\n");
  strcat(g_buf, "publ " PUBL "\n");
  strcat(g_buf, " # bar baz  \n\n"); /* This includes an empty line. */
  strcat(g_buf, "cutoffline"); /* This line cuts off. */
  set_conf_text(g_buf);

  /* Read the new file and check that we can retrieve the values. */
  ck_assert(read_config_file(g_tmpname) == ROUGHTIME_SUCCESS);
  ck_assert(get_config("cert", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, CERT);
  ck_assert(get_config("priv", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, PRIV);
  ck_assert(get_config("publ", &value) == ROUGHTIME_SUCCESS);
  ck_assert_str_eq(value, PUBL);
  /* Check that the cut off key was not stored. */
  ck_assert(get_config("cutoffline", &value) == ROUGHTIME_NOT_FOUND);
  ck_assert_ptr_null(value);
}
END_TEST

/**
 * Set up the test fixture by creating a temporary configuration file and allocating a buffer.
 */
static void setup(void) {
  strcpy(g_tmpname, "test_roughtime_XXXXXX.conf");
  mkstemps(g_tmpname, 5);
  g_buf = malloc(10000);
  ck_assert_ptr_nonnull(g_buf);
}

/**
 * Tear down the text fixture by deleting the temporary configuration file and freeing the buffer.
 */
static void teardown(void) {
  unlink(g_tmpname);
  free(g_buf);
}

/**
 * Adds the test case for config.c to the test suite.
 */
void test_config_add(Suite *s) {
  TCase *tc = tcase_create("Config");
  tcase_add_checked_fixture(tc, setup, teardown);
  tcase_add_test(tc, test_config);
  suite_add_tcase(s, tc);
}

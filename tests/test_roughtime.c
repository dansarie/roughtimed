/* test_roughtime.c

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

/* Adds the tests defined in test_config.c. */
void test_config_add(Suite *s);

/**
 * Creates the Roughtime test suite.
 */
Suite* roughtime_suite(void) {
  Suite *s = suite_create("Roughtime");
  test_config_add(s);
  return s;
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  Suite *s = roughtime_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_VERBOSE);
  int num_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return num_failed;
}

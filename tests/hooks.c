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

int64_t g_gmtime_r_calls  = 0;  /**< Counts number of calls to gmtime_r. */
int64_t g_gmtime_r_failon = -1; /**< Which call to gmtime_r to fail on. */

struct tm *test_gmtime_r(const time_t *restrict timep, struct tm *restrict result) {
  g_gmtime_r_calls += 1;
  if (g_gmtime_r_failon == 0 || g_gmtime_r_calls == g_gmtime_r_failon) {
    return NULL;
  }
  return gmtime_r(timep, result);
}

void fail_gmtime_r(int64_t i) {
  g_gmtime_r_calls = 0;
  g_gmtime_r_failon = i;
}

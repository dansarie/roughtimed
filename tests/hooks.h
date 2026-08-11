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

#ifdef TESTING
struct tm *test_gmtime_r(const time_t *restrict timep, struct tm *restrict result);
#define gmtime_r test_gmtime_r
#endif

/**
 * Sets when test_gmtime_r should fail.
 * @param i sets up to fail on exactly the ith call. A value of zero causes it to always fail.
 * Negative values mean that it never fails.
 */
void fail_gmtime_r(int64_t i);

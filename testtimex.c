/* testtimex.c

   Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se>

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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/timex.h>

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  struct timex t = {0};
  int retval = ntp_adjtime(&t);
  if (retval == -1) {
    printf("ntp_adjtime failed: %s\n", strerror(errno));
    return 1;
  }

  printf("return:   ");
  switch (retval) {
    case TIME_OK:    printf("TIME_OK\n");    break;
    case TIME_INS:   printf("TIME_INS\n");   break;
    case TIME_DEL:   printf("TIME_DEL\n");   break;
    case TIME_OOP:   printf("TIME_OOP\n");   break;
    case TIME_WAIT:  printf("TIME_WAIT\n");  break;
    case TIME_ERROR: printf("TIME_ERROR\n"); break;
  }
  printf("maxerror: %ld\n", t.maxerror);
  printf("esterror: %ld\n", t.esterror);
  printf("ppsfreq:  %ld\n", t.ppsfreq);
  printf("jitter:   %ld\n", t.jitter);
  printf("shift:    %d\n",  t.shift);
  printf("stabil:   %ld\n", t.stabil);
  printf("jitcnt:   %ld\n", t.jitcnt);
  printf("calcnt:   %ld\n", t.calcnt);
  printf("errcnt:   %ld\n", t.errcnt);
  printf("status:   %08x\n", t.status);
  printf("TAI:      %d\n", t.tai);

  return 0;
}

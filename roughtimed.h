/* roughtimed.h

   Copyright (C) 2019-2024 Marcus Dansarie <marcus@dansarie.se>

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

#ifndef __ROUGHTIMED_H__
#define __ROUGHTIMED_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "roughtime-common.h"
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/ip.h>

#define QUEUE_SIZE 16384

typedef struct {
  uint8_t nonc[32];
  struct sockaddr_in6 source;
  struct in6_pktinfo dest;
} __attribute__((aligned(32))) roughtime_query_t;

typedef struct {
  roughtime_query_t queue[QUEUE_SIZE];
  uint32_t cert[152];
  uint8_t priv[256];
  uint32_t queue_size;
  uint32_t queuep;
  uint32_t max_tree_size;
  pthread_mutex_t queue_mutex;
  pthread_cond_t queue_cond;
  int sock;
  bool verbose;
  const char *leap_file_path;
} thread_arguments_t;

#endif /* __ROUGHTIMED_H__ */

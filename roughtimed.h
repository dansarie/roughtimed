/* roughtimed.h
   Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se> */

#ifndef __ROUGHTIMED_H__
#define __ROUGHTIMED_H__

#define _GNU_SOURCE

#include "roughtime-common.h"
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/ip.h>

#define QUEUE_SIZE 16384

typedef struct {
  uint8_t nonc[64];
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

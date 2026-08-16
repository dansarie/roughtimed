/* roughtimed.h

   Copyright (C) 2019-2026 Marcus Dansarie <marcus@dansarie.se>

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

#ifndef ROUGHTIMED_H
#define ROUGHTIMED_H

#include <stddef.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>

#include "roughtime_common.h"

#ifndef VERSION
#define VERSION "(unknown)"
#endif

/** Length of longest possible response message. */
#define MAX_RESPONSE_LEN 800
/** Maximum number of messages to receive at once. */
#define RECV_MAX 1024
/** Maximum allowed length of received message. */
#define MAX_RECV_LEN 1500
/** At least one more than MAX_RECV_LEN, to leading zero for hashing. */
#define MAX_RECV_BUFLEN 1501
/** Roughtime version number. */
#define ROUGHTIME_VERSION 0x8000000C
/** Length of incoming request queue. */
#define QUEUE_SIZE 16384

/** Describes a received Roughtime request packet. */
typedef struct {
  uint8_t msg[MAX_RECV_BUFLEN];  /**< The received Roughtime packet bytes, including the ROUGHTIM
                                      header. A zero byte is prepended to the data, to simplify
                                      hashing. This means that the received packet starts at
                                      index 1. */
  uint32_t len;                  /**< The length of the received Roughtime packet, including the
                                      ROUGHTIM header but excluding the prepended zero byte. */
  uint32_t nonc_offset;          /**< Offset of the raw nonce value in the msg buffer. */
  struct sockaddr_in6 source;    /**< The request packet's source address. */
  struct in6_pktinfo dest;       /**< The request packet's destination address. */
} __attribute__((aligned(32))) roughtime_query_t;

/** Arguments for a response thread. */
typedef struct {
  roughtime_query_t *queue;    /**< The thread's input queue with queries to respond to. */
  uint32_t cert[152];          /**< The server's certificate to include in the responses. */
  uint8_t priv[256];           /**< The server's private key for signing the responses. */
  uint32_t queue_size;         /**< The maximum size of the input queue. */
  uint32_t queuep;             /**< Number of requests in the queue. */
  uint32_t max_tree_size;      /**< Maximum number of messages to include in a Merkle tree. */
  pthread_mutex_t queue_mutex; /**< Mutex for synchronizing access to the queue. */
  pthread_cond_t queue_cond;   /**< Condition variable for singaling that the queue is no longer
                                    empty. */
  int sock;                    /**< File descriptor for the socket to use for sending responses. */
  bool verbose;                /**< Set to true to indicate that threads should write status
                                    messages to standard out when sending responses. */
} thread_arguments_t;

extern bool g_quit; /**< Set to quit by the signal handler to indicate that all threads should
                         quit. */

void signal_handler(int signal);
uint32_t clp2(uint32_t x);
roughtime_result_t sha512_256(uint8_t *in, size_t len, uint8_t *out);
roughtime_result_t compute_merkle(uint8_t *merkle, uint32_t order);
roughtime_result_t add_queries(
    thread_arguments_t *args,
    const roughtime_query_t *queries,
    int *num_queries);
bool check_ver(uint8_t *buf, uint32_t offset, uint32_t length, bool verbose);
void do_stats(
    FILE *restrict stats_file,
    uint64_t *restrict recvcount,
    uint64_t *restrict badcount,
    uint64_t *restrict queuefullcount);
void *response_thread(void *arg);
#endif /* ROUGHTIMED_H */

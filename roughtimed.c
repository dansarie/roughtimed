/* roughtimed.c

   Copyright (C) 2019-2021 Marcus Dansarie <marcus@dansarie.se>

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

#define _GNU_SOURCE

#include "config.h"
#include "roughtimed.h"

#include <endian.h>
#include <errno.h>
#include <fenv.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/timex.h>

#define MAX_PATH_LEN 12
/*
  Header    12
  Header    56 = 7 * 8
    SIG     64
    VER      4
    NONC    64
    PATH   384 = 32 * MAX_PATH_LEN
    SREP    40 = 5 * 8
      DTAI   4
      RADI   4
      LEAP  12
      MIDP   8
      ROOT  32
    CERT   152
    INDX     4
*/
#define MAX_RESPONSE_LEN 840
/* Maximum number of messages to receive at once. */
#define RECV_MAX 1024
/* Maximum allowed length of received message. */
#define MAX_RECV_LEN 1500

bool quit = false; /* Set to quit by the signal handler to indicate that all threads should quit. */

void signal_handler(int signal) {
  fprintf(stderr, "Caught signal.\n");
  quit = true;
}

/* Qsort compare function used by get_leap_events. */
static int compare_leap(const void *e1, const void *e2) {
  uint32_t evt1 = *((uint32_t*)e1) & 0x7fffffff;
  uint32_t evt2 = *((uint32_t*)e2) & 0x7fffffff;
  if (evt1 > evt2) {
    return -1;
  }
  if (evt2 > evt1) {
    return 1;
  }
  return 0;
}

/* Gets a list of leap second events from the system leap second file.
   leap_second_file - path to file.
   events           - return buffer.
   num_events       - buffer size. Set to number of returned items.
   expires          - MJD of leap second file expiry. */
static roughtime_result_t get_leap_events(const char *leap_second_file, uint32_t *events,
    int *num_events, uint32_t *expires) {
  if (leap_second_file == NULL || events == NULL || num_events == NULL || expires == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  FILE *fp = fopen(leap_second_file, "r");
  if (fp == NULL) {
    return ROUGHTIME_FILE_ERROR;
  }

  char *line = NULL;
  size_t lsize = 0;
  int tailast = 0;
  uint32_t evtbuf[1000];
  int bufp = 0;
  *expires = 0;
  bool printed_err = false;
  while (getline(&line, &lsize, fp) >= 0) {
    uint64_t time;
    int tai;
    if (sscanf(line, "%" PRIu64 "%d", &time, &tai) == 2) {
      if (bufp == 1000) {
        if (!printed_err) {
          fprintf(stderr, "Warning: more than 1000 events in leap second file!\n");
          printed_err = true;
        }
        memmove(evtbuf, evtbuf + 1, sizeof(uint32_t) * 999);
        bufp = 999;
      }
      evtbuf[bufp] = time / 86400 + 15020;
      if (tai < tailast) {
        evtbuf[bufp] |= 0x80000000;
      }
      tailast = tai;
      bufp += 1;
    } else if (sscanf(line, "#@ %" PRIu64, &time) == 1) {
      *expires = time / 86400 + 15020;
    }
  }
  free(line);
  fclose(fp);
  qsort(evtbuf, bufp, sizeof(uint32_t), compare_leap);
  if (*num_events > bufp) {
    *num_events = bufp;
  }

  for (int i = 0; i < *num_events; i++) {
    events[i] = evtbuf[i];
  }

  return ROUGHTIME_SUCCESS;
}

/* Converts a timeval struct to a Roughtime timestamp.
   tv   - the timeval to convert
   nano - true if tv_usec in tv is in nanoseconds, false if it is in microseconds. */
static inline uint64_t timeval_to_timestamp(struct timeval tv, bool nano) {
  struct tm tm;
  gmtime_r(&tv.tv_sec, &tm);
  uint64_t mjd = 51545 + ((uint64_t)tm.tm_year - 100) * 365 + ((uint64_t)tm.tm_year - 101) / 4
      + (uint64_t)tm.tm_yday;
  uint64_t usecs = (uint64_t)tm.tm_hour * 3600000000 + (uint64_t)tm.tm_min * 60000000
      + (uint64_t)tm.tm_sec * 1000000;
  if (nano) {
    usecs += nearbyint(tv.tv_usec / 1000.0);
  } else {
    usecs += tv.tv_usec;
  }
  return (mjd << 40) | usecs;
}

/* Ceiling power of 2. */
static inline uint32_t clp2(uint32_t x) {
  x -= 1;
  x |= (x >> 1);
  x |= (x >> 2);
  x |= (x >> 4);
  x |= (x >> 8);
  x |= (x >> 16);
  return x + 1;
}

static inline roughtime_result_t compute_merkle(uint8_t *merkle, uint32_t order) {
  if (merkle == NULL || order > 31) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  if (order == 0) {
    return ROUGHTIME_SUCCESS;
  }
  uint8_t *next_merkle = merkle + 32 * (1 << order);
  SHA512_CTX ctx;
  for (int i = 0; i < (1 << (order - 1)); i++) {
    if (SHA512_Init(&ctx) != 1
        || SHA512_Update(&ctx, "\x01", 1) != 1
        || SHA512_Update(&ctx, merkle + 64 * i, 64) != 1
        || SHA512_Final(next_merkle + 32 * i, &ctx) != 1) {
      fprintf(stderr, "SHA512 error\n");
      return ROUGHTIME_INTERNAL_ERROR;
    }
  }
  return compute_merkle(next_merkle, order - 1);
}

void *response_thread(void *arg) {
  thread_arguments_t *args = (thread_arguments_t*)arg;

  uint8_t *merkle_tree = NULL;
  roughtime_query_t *query_buf = NULL;
  uint8_t *responses = NULL;
  struct mmsghdr *msgvec = NULL;
  struct iovec *iov = NULL;
  uint8_t *control_buf = NULL;
  size_t controllen = CMSG_LEN(sizeof(struct in6_pktinfo));

  uint32_t leap_events[3];
  int num_leap_events = 0;
  time_t last_leap_update = 0;

  fesetround(FE_TONEAREST);

  if (posix_memalign((void**)&merkle_tree, 32, 64 * (args->max_tree_size + 1)) != 0
      || posix_memalign((void**)&query_buf, 32, sizeof(roughtime_query_t) * args->max_tree_size)
          != 0
      || posix_memalign((void**)&responses, 32, args->max_tree_size * MAX_RESPONSE_LEN) != 0
      || posix_memalign((void**)&msgvec, 32, sizeof(struct mmsghdr) * args->max_tree_size) != 0
      || posix_memalign((void**)&iov, 32, sizeof(struct iovec) * args->max_tree_size) != 0
      || posix_memalign((void**)&control_buf, 32, controllen * args->max_tree_size) != 0) {
    fprintf(stderr, "Memory allocation error.\n");
    free(merkle_tree);
    free(query_buf);
    free(responses);
    free(msgvec);
    free(iov);
    free(control_buf);
    quit = true;
    return NULL;
  }
  memset(merkle_tree, 0, 64 * (args->max_tree_size + 1));
  memset(query_buf, 0, sizeof(roughtime_query_t) * args->max_tree_size);
  memset(responses, 0, args->max_tree_size * MAX_RESPONSE_LEN);
  memset(msgvec, 0, sizeof(struct mmsghdr) * args->max_tree_size);
  memset(iov, 0, sizeof(struct iovec) * args->max_tree_size);

  while (!quit) {
    pthread_mutex_lock(&args->queue_mutex);
    if (args->queuep == 0) {
      /* Wait if queue is empty. */
      pthread_cond_wait(&args->queue_cond, &args->queue_mutex);
      if (quit) {
        pthread_mutex_unlock(&args->queue_mutex);
        break;
      }
    }

    /* Copy queries to temporary buffer and release mutex. */
    const uint32_t num_queries = args->queuep > args->max_tree_size ?
        args->max_tree_size : args->queuep;
    memcpy(query_buf, args->queue, sizeof(roughtime_query_t) * num_queries);
    args->queuep -= num_queries;
    memmove(args->queue, args->queue + num_queries, sizeof(roughtime_query_t) * args->queuep);
    pthread_mutex_unlock(&args->queue_mutex);

    SHA512_CTX ctx;
    bool sha512_error = false;
    for (int i = 0; i < num_queries; i++) {
      if (SHA512_Init(&ctx) != 1
          || SHA512_Update(&ctx, "\x00", 1) != 1
          || SHA512_Update(&ctx, query_buf[i].nonc, 64) != 1
          || SHA512_Final(merkle_tree + 32 * i, &ctx) != 1) {
        sha512_error = true;
        break;
      }
    }
    if (sha512_error) {
      fprintf(stderr, "SHA512 error\n");
      continue;
    }
    uint32_t merkle_size = clp2(num_queries);
    memset(merkle_tree + 32 * num_queries, 0, (merkle_size - num_queries) * 32);
    uint32_t merkle_order = __builtin_ctz(merkle_size);
    compute_merkle(merkle_tree, merkle_order);
    /* ROOT */
    uint32_t *root = (uint32_t*)(merkle_tree + 32 * ((1 << (merkle_order + 1)) - 2));

    /* MIDP */
    struct timex timex = {0};
    ntp_adjtime(&timex);
    timex.time.tv_sec += timex.tai - 10; /* Fixed 10 second offset between TAI and Unix time. */
    uint64_t midp = timeval_to_timestamp(timex.time, timex.status & STA_NANO);
    uint32_t mjd = midp >> 40;
    midp = htole64(midp);

    /* RADI */
    uint32_t radi = htole32(timex.maxerror);
    /* If maxerror is very small, we trust the esterror field. */
    if (timex.maxerror < 10000) {
      radi = htole32(timex.esterror);
    }

    /* SREP */
    uint32_t srep_len = 140;
    uint8_t srep[140];
    roughtime_result_t res;

    /* DTAI */
    uint32_t tai = timex.tai;
    if (timex.tai < 0) {
      tai = 0x80000000 | -timex.tai;
    }
    tai = htole32(tai);

    /* LEAP */
    if (args->leap_file_path != NULL && labs(timex.time.tv_sec - last_leap_update) > 60) {
      last_leap_update = timex.time.tv_sec;
      num_leap_events = 3;
      uint32_t leap_events_expire = 0;
      if (get_leap_events(args->leap_file_path, leap_events, &num_leap_events,
          &leap_events_expire) != ROUGHTIME_SUCCESS) {
        fprintf(stderr, "Error when reading leap second file.\n");
        num_leap_events = 0;
      } else if (leap_events_expire <= mjd) {
        num_leap_events = 0;
      }
      for (int i = 0; i < num_leap_events; i++) {
        leap_events[i] = htole32(leap_events[i]);
      }
    }

    if ((res = create_roughtime_packet(srep, &srep_len, 5,
        "DTAI", 4, &tai,
        "RADI", 4, &radi,
        "LEAP", 4 * num_leap_events, leap_events,
        "MIDP", 8, &midp,
        "ROOT", 32, root)) != ROUGHTIME_SUCCESS) {
      fprintf(stderr, "Error when creating SREP packet.\n");
      continue;
    }
    /* SIG */
    uint32_t srep_sig[16];
    if (sign(srep, srep_len, SIGNED_RESPONSE_CONTEXT, SIGNED_RESPONSE_CONTEXT_LEN,
        (uint8_t*)srep_sig, args->priv) != ROUGHTIME_SUCCESS) {
      fprintf(stderr, "Signing failure.\n");
      continue;
    }

    uint32_t ver = htole32(0x80000003);
    uint8_t nonc[64] = {0};
    uint32_t indx = 0;
    uint32_t path_len = merkle_order * 32;
    uint32_t path[MAX_PATH_LEN * 32];
    uint32_t response_len = MAX_RESPONSE_LEN - 12;
    if ((res = create_roughtime_packet(responses + 12, &response_len, 7,
        "SIG", 64, srep_sig,
        "VER", 4, &ver,
        "NONC", 64, nonc,
        "PATH", path_len, path,
        "SREP", srep_len, srep,
        "CERT", 152, args->cert,
        "INDX", 4, &indx)) != ROUGHTIME_SUCCESS) {
      fprintf(stderr, "Error when creating response packet.\n");
      continue;
    }

    /* Get value offsets. */
    roughtime_header_t res_header;
    uint32_t nonc_offset, nonc_len, path_offset, indx_offset, indx_len;
    if (parse_roughtime_header(responses + 12, response_len, &res_header) != ROUGHTIME_SUCCESS
        || get_header_tag(&res_header, str_to_tag("NONC"), &nonc_offset, &nonc_len)
            != ROUGHTIME_SUCCESS
        || get_header_tag(&res_header, str_to_tag("PATH"), &path_offset, &path_len)
            != ROUGHTIME_SUCCESS
        || get_header_tag(&res_header, str_to_tag("INDX"), &indx_offset, &indx_len)
            != ROUGHTIME_SUCCESS) {
      fprintf(stderr, "Error when creating response packet.\n");
      continue;
    }
    nonc_offset += 12;
    path_offset += 12;
    indx_offset += 12;

    /* Create packet header. */
    *((uint64_t*)responses) = htole64(0x4d49544847554f52);
    *((uint32_t*)(responses + 8)) = htole32(response_len);
    response_len += 12;


    /* Create multiple copies of template response packet. */
    for (int i = 1; i < num_queries; i++) {
      memcpy(responses + i * response_len, responses, response_len);
    }

    /* Set response packets' PATH tag. */
    uint8_t *merklep = merkle_tree;
    for (int level = 0; level < merkle_order; level++) {
      for (int i = 0; i < 1 << (merkle_order - level); i++) {
        int idx = (i ^ 1) << level;
        uint8_t *responsep = responses + idx * response_len + path_offset + level * 32;
        for (int k = 0; k < 1 << level && (idx | k) < num_queries; k++) {
          memcpy(responsep + k * response_len, merklep, 32);
        }
        merklep += 32;
      }
    }

    for (int i = 0; i < num_queries; i++) {
      /* Set NONC. */
      memcpy(responses + i * response_len + nonc_offset, query_buf[i].nonc, 64);
      /* Set INDX. */
      *((uint32_t*)(responses + i * response_len + indx_offset)) = htole32(i);

      /* Prepare structs for sendmmsg. */
      iov[i].iov_base = responses + i * response_len;
      iov[i].iov_len = response_len;
      msgvec[i].msg_hdr.msg_name = &query_buf[i].source;
      msgvec[i].msg_hdr.msg_namelen = sizeof(query_buf[i].source);
      msgvec[i].msg_hdr.msg_iov = iov + i;
      msgvec[i].msg_hdr.msg_iovlen = 1;
      msgvec[i].msg_hdr.msg_control = control_buf + controllen * i;
      msgvec[i].msg_hdr.msg_controllen = controllen;
      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgvec[i].msg_hdr);
      cmsg->cmsg_level = IPPROTO_IPV6;
      cmsg->cmsg_type = IPV6_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
      *(struct in6_pktinfo*)CMSG_DATA(cmsg) = query_buf[i].dest;
      msgvec[i].msg_hdr.msg_flags = 0;
      msgvec[i].msg_len = 0;
    }

    /* Send responses. */
    unsigned int to_send = num_queries;
    unsigned int num_sent = 0;
    bool retry = true;
    while (to_send > 0) {
      int sent = sendmmsg(args->sock, msgvec + num_sent, to_send, 0);
      if (sent < 0) {
        if(quit) {
          break;
        }
        if (retry) {
          retry = false;
          continue;
        }
        fprintf(stderr, "Error when sending responses: %s. %u unsent responses. \n",
            strerror(errno), to_send);
        break;
      }
      num_sent += sent;
      to_send -= sent;
    }

    if (args->verbose) {
      pthread_mutex_lock(&args->queue_mutex);
      uint32_t queuep = args->queuep;
      pthread_mutex_unlock(&args->queue_mutex);
      printf("Sent %4d responses @ %4" PRIu32 " bytes each. Queue size: %5" PRIu32 "\n",
          num_sent, response_len, queuep);
    }
  }

  free(merkle_tree);
  free(query_buf);
  free(responses);
  free(msgvec);
  free(iov);
  free(control_buf);
  return NULL;
}

/* Add received queries to a thread's input queue. Returns ROUGHTIME_SUCCESS when successful and
   ROUGHTIME_QUEUE_FULL if no queries could be added.
   thread       A thread.
   args         The thread's arguments.
   queries      A query buffer.
   num_queries  The number of queries to attempt to add to the queue. On return, num_queries
                contains the number of queries that was actually added to the queue. */
static roughtime_result_t add_queries(pthread_t *thread, thread_arguments_t *args,
    const roughtime_query_t *queries, int *num_queries) {

  if (thread == NULL || args == NULL || queries == NULL || num_queries == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  if (*num_queries <= 0) {
    return ROUGHTIME_SUCCESS;
  }

  pthread_mutex_lock(&args->queue_mutex);
  int free = (int)args->queue_size - args->queuep;
  if (free <= 0) {
    pthread_mutex_unlock(&args->queue_mutex);
    return ROUGHTIME_QUEUE_FULL;
  }
  uint32_t copy = free >= *num_queries ? *num_queries : free;
  memcpy(args->queue + args->queuep, queries, sizeof(roughtime_query_t) * copy);
  args->queuep += copy;
  *num_queries = copy;
  pthread_cond_signal(&args->queue_cond);
  pthread_mutex_unlock(&args->queue_mutex);

  return ROUGHTIME_SUCCESS;
}

static void do_stats(FILE *restrict stats_file, uint64_t *restrict recvcount,
    uint64_t *restrict badcount, uint64_t *restrict queuefullcount) {

  if (stats_file == NULL) {
    return;
  }
  struct timex timex = {0};
  ntp_adjtime(&timex);
  timex.time.tv_sec += timex.tai - 10; /* Fixed 10 second offset between TAI and Unix time. */
  struct tm stats_tm;
  gmtime_r(&timex.time.tv_sec, &stats_tm);
  static int count_minute = -1;
  if (count_minute == -1) {
    count_minute = stats_tm.tm_min;
    return;
  }
  if (count_minute == stats_tm.tm_min) {
    return;
  }
  fprintf(stats_file, "%04d-%02d-%02dT%02d:%02d:%02dZ %10"
      PRIu64 " %10" PRIu64 " %10" PRIu64 " %10ld %10ld\n",
      stats_tm.tm_year + 1900, stats_tm.tm_mon + 1, stats_tm.tm_mday,
      stats_tm.tm_hour, stats_tm.tm_min, stats_tm.tm_sec,
      *recvcount, *badcount, *queuefullcount, timex.maxerror, timex.esterror);
  fflush(stats_file);
  *recvcount = *badcount = *queuefullcount = 0;
  count_minute = stats_tm.tm_min;
  return;
}

int main(int argc, char *argv[]) {

  roughtime_result_t err = ROUGHTIME_SUCCESS;
  pthread_t *threads = NULL;
  thread_arguments_t *arguments = NULL;
  uint8_t *control_buf = NULL;
  int sock = -1;
  long num_response_threads = 0;
  uint8_t cert[153];
  uint8_t priv[33];
  FILE *stats_file = NULL;
  FILE *leap_file = NULL;

  /* Parse command line options. */
  char config_file_name[1000];
  strcpy(config_file_name, "/etc/roughtimed.conf");
  bool verbose = false;
  int optchar;
  while ((optchar = getopt(argc, argv, "f:v")) >= 0) {
    switch (optchar) {
      case 'f':
        RETURN_IF(strlen(optarg) >= 1000, ROUGHTIME_BAD_ARGUMENT, "Config file name too long.");
        strcpy(config_file_name, optarg);
        break;
      case 'v':
        printf("Verbose output enabled.\n");
        verbose = true;
        break;
      default:
        fprintf(stderr, "Unknown option parsed.\n");
        return 1;
    }
  }

  /* Read config file and check if it contains the required statements. */
  fprintf(stderr, "Using config file %s\n", config_file_name);
  struct stat statbuf;
  const char *b64cert;
  const char *b64priv;
  RETURN_IF(stat(config_file_name, &statbuf) != 0, ROUGHTIME_FILE_ERROR,
      "Running stat on config file failed.");
  RETURN_IF(statbuf.st_mode & (S_IROTH | S_IWOTH), ROUGHTIME_FILE_ERROR,
      "Config file is world readable or writable.");
  RETURN_ON_ERROR(read_config_file(config_file_name), "Error when reading config file.");
  RETURN_ON_ERROR(get_config("cert", &b64cert), "Missing cert line in configuration file.");
  RETURN_ON_ERROR(get_config("priv", &b64priv), "Missing priv line in configuration file.");

  /* Open statistics file if specified. */
  const char *stats_path;
  if (get_config("stats", &stats_path) == ROUGHTIME_SUCCESS) {
    RETURN_IF((stats_file = fopen(stats_path, "a")) == NULL, ROUGHTIME_FILE_ERROR,
        "Error when opening statistics output file.");
  }

  /* Check if leap second file can be opened. */
  const char *leap_file_path;
  if (get_config("leap", &leap_file_path) == ROUGHTIME_SUCCESS) {
    RETURN_IF((leap_file = fopen(leap_file_path, "r")) == NULL, ROUGHTIME_FILE_ERROR,
        "Error when opening leap second file");
    fclose(leap_file);
    leap_file = NULL;
  }

  const char *path_len;
  uint32_t max_tree_size = 1 << MAX_PATH_LEN;
  if (get_config("max_path_len", &path_len) == ROUGHTIME_SUCCESS) {
    errno = 0;
    int max_path_len = atoi(path_len);
    if (errno == 0 || max_path_len >= 0 || max_path_len <= MAX_PATH_LEN) {
      max_tree_size = 1 << max_path_len;
    } else {
      fprintf(stderr, "Bad max_path_len in config file. Using default.\n");
    }
  }

  /* Parse and check the certificate and private key from the configuration file. */
  size_t len_cert = 153;
  size_t len_priv = 33;
  RETURN_ON_ERROR(from_base64((uint8_t*)b64cert, cert, &len_cert),
      "Conversion from base64 failed.");
  RETURN_ON_ERROR(from_base64((uint8_t*)b64priv, priv, &len_priv),
      "Conversion from base64 failed.");
  RETURN_IF(len_cert != 152, ROUGHTIME_FORMAT_ERROR, "Wrong certificate size.");
  RETURN_IF(len_priv != 32, ROUGHTIME_FORMAT_ERROR, "Wrong private key size.");
  
  roughtime_header_t cert_header, dele_header;
  uint32_t dele_offset, dele_length, sig_offset, sig_length, mint_offset, mint_length,
      maxt_offset, maxt_length, pubk_offset, pubk_length;
  RETURN_ON_ERROR(parse_roughtime_header(cert, 152, &cert_header),
      "Error when parsing certificate.");
  RETURN_ON_ERROR(get_header_tag(&cert_header, str_to_tag("DELE"), &dele_offset, &dele_length),
      "Error when parsing DELE tag in certificate header.");
  RETURN_ON_ERROR(get_header_tag(&cert_header, str_to_tag("SIG"), &sig_offset, &sig_length),
      "Error when parsing SIG tag in certificate header.");
  RETURN_IF(sig_length != 64, ROUGHTIME_FORMAT_ERROR, "Wrong certificate signature size.");
  RETURN_ON_ERROR(parse_roughtime_header(cert + dele_offset, 72, &dele_header),
      "Error when parsing certificate DELE tag.");
  RETURN_ON_ERROR(get_header_tag(&dele_header, str_to_tag("MINT"), &mint_offset, &mint_length),
      "Error when parsing MINT tag in certificate DELE header.");
  RETURN_ON_ERROR(get_header_tag(&dele_header, str_to_tag("MAXT"), &maxt_offset, &maxt_length),
      "Error when parsing MAXT tag in certificate DELE header.");
  RETURN_ON_ERROR(get_header_tag(&dele_header, str_to_tag("PUBK"), &pubk_offset, &pubk_length),
      "Error when parsing PUBK tag in certificate DELE header");
  RETURN_IF(mint_length != 8, ROUGHTIME_FORMAT_ERROR, "Bad MINT size in certificate.");
  RETURN_IF(maxt_length != 8, ROUGHTIME_FORMAT_ERROR, "Bad MAXT size in certificate.");
  RETURN_IF(pubk_length != 32, ROUGHTIME_FORMAT_ERROR, "Bad PUBK size in certificate.");


  /* Set a timezone that respects leap seconds. */
  RETURN_IF(setenv("TZ", "right/UTC", 1) != 0, ROUGHTIME_INTERNAL_ERROR,
      "Error when setting TZ environment variable.");
  tzset();

  /* Check that the time zone was set successfully and that it handles leap seconds as expected. */
  struct tm leap_test_tm;
  time_t leap_test_time = 1483228826; /* 2016-12-31 23:59:60 */
  gmtime_r(&leap_test_time, &leap_test_tm);
  RETURN_IF(leap_test_tm.tm_sec != 60, ROUGHTIME_INTERNAL_ERROR, "Invalid leap second handling.");

  /* Wait for NTP server to synchronize system time. */
  struct timex timex = {0};
  int adjtime_ret = ntp_adjtime(&timex);
  if (adjtime_ret == TIME_ERROR) {
    fprintf(stderr, "System clock not synchronized. Waiting for time synchronization.\n");
  } else if (timex.maxerror > 1000000) {
    fprintf(stderr, "Time error too high. Waiting for time synchronization.\n");
  }
  int time_sync_wait = 0;
  while (adjtime_ret == TIME_ERROR || timex.maxerror > 1000000) {
    RETURN_IF(time_sync_wait++ > 600, ROUGHTIME_INTERNAL_ERROR,
        "Gave up waiting for time synchronization.");
    usleep(100000);
    adjtime_ret = ntp_adjtime(&timex);
  }
  RETURN_IF(timex.tai == 0, ROUGHTIME_INTERNAL_ERROR, "TAI offset not set.");

  int portnum = 2002;
  const char *port_config;
  if (get_config("port", &port_config) == ROUGHTIME_SUCCESS) {
    errno = 0;
    portnum = atoi(port_config);
    RETURN_IF(errno != 0 || portnum < 0 || portnum >= 65536, ROUGHTIME_FORMAT_ERROR,
        "Bad port argument in config file.");
  }

  /* Create and bind socket. */
  sock = socket(AF_INET6, SOCK_DGRAM, 0);
  RETURN_IF(sock == -1, ROUGHTIME_INTERNAL_ERROR, "Error when creating socket.");
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(portnum);
  addr.sin6_addr = in6addr_any;
  RETURN_IF(bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in6)) != 0,
      ROUGHTIME_INTERNAL_ERROR, "Error when binding socket.");

  /* Set socket receive timeout. */
  struct timeval timeout = {0, 1000}; /* 1000 microseconds. */
  const int one = 1;
  RETURN_IF(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) != 0
      || setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(int)) != 0,
      ROUGHTIME_INTERNAL_ERROR, "Error when changing socket settings.");

  /* Calculate the number of response threads that should be spawned and check for a custom value
     in the configuration file. */
  num_response_threads = sysconf(_SC_NPROCESSORS_ONLN) - 1;
  if (num_response_threads < 1) {
    num_response_threads = 1;
  }
  const char *threads_config;
  if (get_config("threads", &threads_config) == ROUGHTIME_SUCCESS) {
    errno = 0;
    long nthreads = atoi(threads_config);
    if (errno != 0 || nthreads < 2) {
      fprintf(stderr, "Bad threads argument in config file. Must be at least 2. Using default.\n");
    } else {
      num_response_threads = nthreads - 1;
    }
  }

  RETURN_IF(signal(SIGINT, signal_handler) == SIG_ERR
      || signal(SIGTERM, signal_handler) == SIG_ERR, ROUGHTIME_INTERNAL_ERROR,
      "Error when registering signal handler.");

  /* References to the response threads and their arguments. */
  threads = calloc(num_response_threads, sizeof(pthread_t));
  arguments = calloc(num_response_threads, sizeof(thread_arguments_t));
  RETURN_IF(threads == NULL || arguments == NULL, ROUGHTIME_MEMORY_ERROR,
      "Memory allocation error.");

  /* Spawn threads. */
  for (long i = 0; i < num_response_threads; i++) {
    arguments[i].queue_size = QUEUE_SIZE;
    arguments[i].queuep = 0;
    arguments[i].max_tree_size = max_tree_size;
    arguments[i].sock = sock;
    arguments[i].verbose = verbose;
    arguments[i].leap_file_path = leap_file_path;
    memcpy(arguments[i].cert, cert, 152);
    memcpy(arguments[i].priv, priv, 32);
    pthread_mutex_init(&arguments[i].queue_mutex, NULL);
    int ret;
    if ((ret = pthread_cond_init(&arguments[i].queue_cond, NULL)) != 0
        || pthread_create(&threads[i], NULL, response_thread, &arguments[i]) != 0) {
      quit = true;

      /* Signal all threads, wait for them to quit and destroy all successfully initialized
         condition variables and mutexes. */
      for (long k = 0; k < i; k++) {
        pthread_cond_signal(&arguments[k].queue_cond);
      }
      for (long k = 0; k < i; k++) {
        pthread_join(threads[k], NULL);
        pthread_cond_destroy(&arguments[k].queue_cond);
        pthread_mutex_destroy(&arguments[k].queue_mutex);
      }
      pthread_mutex_destroy(&arguments[i].queue_mutex);
      if (ret == 0) {
        pthread_cond_destroy(&arguments[i].queue_cond);
      }
      RETURN_IF(1, ROUGHTIME_INTERNAL_ERROR, "Error when creating threads.");
    }
  }

  /* Zero out potentially sensitive arrays that aren't needed anymore. */
  explicit_bzero(cert, 153);
  explicit_bzero(priv, 33);

  fprintf(stderr, "roughtimed version %s started. (%ld threads)\n",
      VERSION, num_response_threads + 1);
  fprintf(stderr, "Build time: %s %s\n", __DATE__, __TIME__);

  uint64_t recvcount = 0;
  uint64_t badcount = 0;
  uint64_t queuefullcount = 0;
  long next_thread = 0;

  uint8_t buf[MAX_RECV_LEN * RECV_MAX];
  struct sockaddr_in6 sources[RECV_MAX];
  struct iovec iov[RECV_MAX];
  struct mmsghdr msgvec[RECV_MAX];
  size_t controllen = CMSG_LEN(sizeof(struct in6_pktinfo));
  control_buf = malloc(sizeof(uint8_t) * controllen * RECV_MAX);
  RETURN_IF(control_buf == NULL, ROUGHTIME_MEMORY_ERROR, "Memory allocation error.");
  memset(sources, 0, sizeof(struct sockaddr_in6) * RECV_MAX);
  memset(control_buf, 0, controllen * RECV_MAX);

  /* Main receive loop. */
  while (!quit) {
    for (int i = 0; i < RECV_MAX; i++) {
      iov[i].iov_base = buf + i * MAX_RECV_LEN;
      iov[i].iov_len = MAX_RECV_LEN;
      msgvec[i].msg_hdr.msg_name = sources + i;
      msgvec[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
      msgvec[i].msg_hdr.msg_iov = iov + i;
      msgvec[i].msg_hdr.msg_iovlen = 1;
      msgvec[i].msg_hdr.msg_control = &control_buf[controllen * i];
      msgvec[i].msg_hdr.msg_controllen = controllen;
      msgvec[i].msg_hdr.msg_flags = 0;
      msgvec[i].msg_len = 0;
    }
    struct timespec timeout = {0, 1000000}; /* 1000000 nanoseconds. */

    int received = recvmmsg(sock, msgvec, RECV_MAX, 0, &timeout);
    roughtime_query_t queries[RECV_MAX];

    int num_queries = 0;
    for (int i = 0; i < received; i++) {
      roughtime_header_t header;
      uint32_t ver_offset, nonc_offset, len;
      /* Ignore non-compliant packets and receive timeouts. */
      if (msgvec[i].msg_len < MAX_RESPONSE_LEN
          || le64toh(*(uint64_t*)(buf + i * MAX_RECV_LEN)) != 0x4d49544847554f52 /* ROUGHTIM */
          || le32toh(*(uint32_t*)(buf + i * MAX_RECV_LEN + 8)) != msgvec[i].msg_len - 12
          || parse_roughtime_header(buf + i * MAX_RECV_LEN + 12, msgvec[i].msg_len - 12, &header)
              != ROUGHTIME_SUCCESS
          || get_header_tag(&header, str_to_tag("VER"), &ver_offset, &len) != ROUGHTIME_SUCCESS
          || len == 0
          || get_header_tag(&header, str_to_tag("NONC"), &nonc_offset, &len) != ROUGHTIME_SUCCESS
          || len != 64) {
        if (msgvec[i].msg_len > 0) {
          badcount += 1;
        }
        continue;
      }
      memcpy(&queries[num_queries].nonc, buf + i * MAX_RECV_LEN + nonc_offset + 12, 64);
      queries[num_queries].source = sources[i];

      /* Get control message with destination IP address. */
      struct cmsghdr *cmsg;
      for (cmsg = CMSG_FIRSTHDR(&msgvec[i].msg_hdr); cmsg != NULL;
          cmsg = CMSG_NXTHDR(&msgvec[i].msg_hdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
          queries[num_queries].dest = *(struct in6_pktinfo*)CMSG_DATA(cmsg);
          break;
        }
      }
      num_queries += 1;
    }

    int queryp = 0;
    for (int i = 0; num_queries > 0 && i < num_response_threads; i++) {
      int num = num_queries;
      add_queries(&threads[next_thread], &arguments[next_thread], queries + queryp, &num);
      num_queries -= num;
      recvcount += num;
      queryp += num;
      next_thread = (next_thread + 1) % num_response_threads;
    }
    queuefullcount += num_queries;

    do_stats(stats_file, &recvcount, &badcount, &queuefullcount);
  }

  

error:
  printf("Quitting.\n");
  quit = true;
  if (arguments != NULL && threads != NULL) {
    /* Signal all threads and wait for them to quit. */
    for (long i = 0; i < num_response_threads; i++) {
      pthread_cond_signal(&arguments[i].queue_cond);
    }
    for (long i = 0; i < num_response_threads; i++) {
      pthread_join(threads[i], NULL);
      pthread_mutex_destroy(&arguments[i].queue_mutex);
      pthread_cond_destroy(&arguments[i].queue_cond);
    }
  }
  explicit_bzero(cert, 153);
  explicit_bzero(priv, 33);
  if (arguments != NULL) {
    explicit_bzero(arguments, sizeof(thread_arguments_t) * num_response_threads);
  }
  clear_config();
  free(threads);
  free(arguments);
  free(control_buf);
  if (sock != -1) {
    close(sock);
  }
  if (stats_file != NULL) {
    fclose(stats_file);
  }
  if (leap_file != NULL) {
    fclose(leap_file);
  }
  if (err == ROUGHTIME_SUCCESS) {
    return 0;
  }
  return 1;
}

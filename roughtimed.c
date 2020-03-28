/* roughtimed.c
   Copyright (C) 2019 Marcus Dansarie <marcus@dansarie.se> */

#define _GNU_SOURCE

#include "config.h"
#include "roughtimed.h"

#include <endian.h>
#include <errno.h>
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
  Header    40
    SREP    24
      ROOT  32
      MIDP   8
      RADI   4
    SIG     64
    CERT   152
    INDX     4
    PATH   384 = 32 * MAX_PATH_LEN
*/
#define MAX_RESPONSE_LEN 712
#define RECV_MAX 1024
#define MAX_RECV_LEN 1500

/* The RETURN macros simplify clearing and freeing resources on early return on error from main. */
#define RETURN_CONF(x)\
  clear_config();\
  return x;

#define RETURN_CONF_STATS_PRIV(x)\
  explicit_bzero(cert, 153);\
  explicit_bzero(priv, 33);\
  fclose(stats_file);\
  clear_config();\
  return x;

#define RETURN_CONF_STATS_PRIV_SOCK(x)\
  close(sock);\
  explicit_bzero(cert, 153);\
  explicit_bzero(priv, 33);\
  fclose(stats_file);\
  clear_config();\
  return x;

#define RETURN_CONF_STATS_PRIV_SOCK_ARGS(x)\
  explicit_bzero(arguments, sizeof(thread_arguments_t) * num_response_threads);\
  free(arguments);\
  close(sock);\
  explicit_bzero(cert, 153);\
  explicit_bzero(priv, 33);\
  fclose(stats_file);\
  clear_config();\
  return x;

bool quit = false; /* Set to quit by the signal handler to indicate that all threads should quit. */

void signal_handler(int signal) {
  fprintf(stderr, "Caught signal.\n");
  quit = true;
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
    usecs += round(tv.tv_usec / 1000.0);
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
    uint64_t midp = htole64(timeval_to_timestamp(timex.time, timex.status & STA_NANO));

    /* RADI */
    uint32_t radi = htole32(timex.maxerror);
    /* If maxerror is very small, we trust the esterror field. */
    if (timex.maxerror < 10000) {
      radi = htole32(timex.esterror);
    }

    /* SREP */
    uint32_t srep_len = 68;
    uint8_t srep[68];
    roughtime_result_t res;
    if ((res = create_roughtime_packet(srep, &srep_len, 3,
        "ROOT", 32, root,
        "MIDP", 8, &midp,
        "RADI", 4, &radi)) != ROUGHTIME_SUCCESS) {
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

    uint32_t indx = 0;
    uint32_t path_len = merkle_order * 32;
    uint32_t path[MAX_PATH_LEN * 32];
    uint32_t response_len = MAX_RESPONSE_LEN;
    if ((res = create_roughtime_packet(responses, &response_len, 5,
        "SREP", srep_len, srep,
        "SIG", 64, srep_sig,
        "CERT", 152, args->cert,
        "INDX", 4, &indx,
        "PATH", path_len, path)) != ROUGHTIME_SUCCESS) {
      fprintf(stderr, "Error when creating response packet.\n");
      continue;
    }

    /* Create multiple copies of template response packet. */
    for (int i = 1; i < num_queries; i++) {
      memcpy(responses + i * response_len, responses, response_len);
    }

    const int index_offset = 324;
    const int path_offset = index_offset + 4;

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
      /* Set index. */
      *((uint32_t*)(responses + index_offset + i * response_len)) = htole32(i);

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

  /* Parse command line options. */
  char config_file_name[1000];
  strcpy(config_file_name, "/etc/roughtimed.conf");
  bool verbose = false;
  int optchar;
  while ((optchar = getopt(argc, argv, "f:v")) >= 0) {
    switch (optchar) {
      case 'f':
        if (strlen(optarg) >= 1000) {
          fprintf(stderr, "Config file name too long.\n");
          return 1;
        }
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
  if (stat(config_file_name, &statbuf) != 0) {
    fprintf(stderr, "Running stat on config file failed: %s\n", strerror(errno));
    return 1;
  }
  if (statbuf.st_mode & (S_IROTH | S_IWOTH)) {
    fprintf(stderr, "Config file is world readable or writable.\n");
    return 1;
  }

  if (read_config_file(config_file_name) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when reading config file: %s\n", strerror(errno));
    RETURN_CONF(1);
  }
  const char *b64cert;
  const char *b64priv;
  if (get_config("cert", &b64cert) != ROUGHTIME_SUCCESS
     || get_config("priv", &b64priv) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Missing cert or priv line in configuration file.\n");
    RETURN_CONF(1);
  }

  const char *stats_path;
  FILE *stats_file = NULL;
  if (get_config("stats", &stats_path) == ROUGHTIME_SUCCESS) {
    if ((stats_file = fopen(stats_path, "a")) == NULL) {
      fprintf(stderr, "Error when opening statistics output file.\n");
      RETURN_CONF(1);
    }
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
  uint8_t cert[153];
  uint8_t priv[33];
  size_t len_cert = 153;
  size_t len_priv = 33;
  if (from_base64((uint8_t*)b64cert, cert, &len_cert) != ROUGHTIME_SUCCESS
      || from_base64((uint8_t*)b64priv, priv, &len_priv) != ROUGHTIME_SUCCESS
      || len_cert != 152 || len_priv != 32) {
    fprintf(stderr, "Conversion from base64 failed.\n");
    RETURN_CONF_STATS_PRIV(1);
  }
  roughtime_header_t cert_header, dele_header;
  uint32_t dele_offset, dele_length, sig_offset, sig_length, mint_offset, mint_length,
      maxt_offset, maxt_length, pubk_offset, pubk_length;
  if (parse_roughtime_header(cert, 152, &cert_header) != ROUGHTIME_SUCCESS
      || get_header_tag(&cert_header, str_to_tag("DELE"), &dele_offset, &dele_length)
          != ROUGHTIME_SUCCESS
      || get_header_tag(&cert_header, str_to_tag("SIG"), &sig_offset, &sig_length)
          != ROUGHTIME_SUCCESS
      || sig_length != 64
      || parse_roughtime_header(cert + dele_offset, 72, &dele_header)
          != ROUGHTIME_SUCCESS
      || get_header_tag(&dele_header, str_to_tag("MINT"), &mint_offset, &mint_length)
          != ROUGHTIME_SUCCESS
      || get_header_tag(&dele_header, str_to_tag("MAXT"), &maxt_offset, &maxt_length)
          != ROUGHTIME_SUCCESS
      || get_header_tag(&dele_header, str_to_tag("PUBK"), &pubk_offset, &pubk_length)
          != ROUGHTIME_SUCCESS
      || mint_length != 8 || maxt_length != 8 || pubk_length != 32) {
    fprintf(stderr, "Bad CERT in configuration file.\n");
    RETURN_CONF_STATS_PRIV(1);
  }

  /* Set a timezone that respects leap seconds. */
  if (setenv("TZ", "right/UCT", 1) != 0) {
    fprintf(stderr, "Error setting TZ environment variable.\n");
    RETURN_CONF_STATS_PRIV(1);
  }
  tzset();

  /* Check that we set the time zone successfully and that it handles leap seconds as expected. */
  struct tm leap_test_tm;
  time_t leap_test_time = 1483228826; /* 2016-12-31 23:59:60 */
  gmtime_r(&leap_test_time, &leap_test_tm);
  if (leap_test_tm.tm_sec != 60) {
    fprintf(stderr, "Invalid leap second handling.\n");
    RETURN_CONF_STATS_PRIV(1);
  }

  struct timex timex = {0};
  int adjtime_ret = ntp_adjtime(&timex);
  if (timex.tai == 0) {
    fprintf(stderr, "TAI offset not set.\n");
    RETURN_CONF_STATS_PRIV(1);
  }
  if (adjtime_ret == TIME_ERROR) {
    fprintf(stderr, "System clock not synchronized. Waiting for time synchronization.\n");
  } else if (timex.maxerror > 1000000) {
    fprintf(stderr, "Time error too high. Waiting for time synchronization.\n");
  }
  int time_sync_wait = 0;
  while (adjtime_ret == TIME_ERROR || timex.maxerror > 1000000) {
    if (time_sync_wait++ > 600) {
      fprintf(stderr, "Gave up waiting for time synchronization.\n");
      RETURN_CONF_STATS_PRIV(1);
    }
    usleep(100000);
    adjtime_ret = ntp_adjtime(&timex);
  }

  int portnum = 2002;
  const char *port_config;
  if (get_config("port", &port_config) == ROUGHTIME_SUCCESS) {
    errno = 0;
    portnum = atoi(port_config);
    if (errno != 0 || portnum < 0 || portnum >= 65536) {
      fprintf(stderr, "Bad port argument in config file.\n");
      RETURN_CONF_STATS_PRIV(1);
    }
  }

  /* Create and bind socket. */
  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == -1) {
    fprintf(stderr, "Error when creating socket: %s\n", strerror(errno));
    RETURN_CONF_STATS_PRIV(1);
  }
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(portnum);
  addr.sin6_addr = in6addr_any;
  if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in6)) != 0) {
    fprintf(stderr, "Error when binding socket: %s\n", strerror(errno));
    RETURN_CONF_STATS_PRIV_SOCK(1);
  }

  /* Set socket receive timeout. */
  struct timeval timeout = {0, 1000}; /* 1000 microseconds. */
  const int one = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) != 0
      || setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(int)) != 0) {
    fprintf(stderr, "Error when changing socket settings: %s\n", strerror(errno));
    RETURN_CONF_STATS_PRIV_SOCK(1);
    return 1;
  }

  /* Calculate the number of response threads that should be spawned and check for a custom value
     in the configuration file. */
  long num_response_threads = sysconf(_SC_NPROCESSORS_ONLN) - 1;
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

  if (signal(SIGINT, signal_handler) == SIG_ERR
      || signal(SIGTERM, signal_handler) == SIG_ERR) {
    fprintf(stderr, "Error when registering signal handler: %s\n", strerror(errno));
    RETURN_CONF_STATS_PRIV_SOCK(1);
  }

  /* References to the response threads and their arguments. */
  pthread_t threads[num_response_threads];
  thread_arguments_t *arguments = malloc(sizeof(thread_arguments_t) * num_response_threads);
  if (arguments == NULL) {
    RETURN_CONF_STATS_PRIV_SOCK(1);
  }
  memset(threads, 0, sizeof(pthread_t) * num_response_threads);
  memset(arguments, 0, sizeof(thread_arguments_t) * num_response_threads);

  /* Spawn threads. */
  for (long i = 0; i < num_response_threads; i++) {
    memset(&arguments[i], 0, sizeof(thread_arguments_t));
    arguments[i].queue_size = QUEUE_SIZE;
    arguments[i].queuep = 0;
    arguments[i].max_tree_size = max_tree_size;
    arguments[i].sock = sock;
    arguments[i].verbose = verbose;
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
      fprintf(stderr, "Error when creating pthread.\n");
      RETURN_CONF_STATS_PRIV_SOCK_ARGS(1);
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
  uint8_t control_buf[controllen * RECV_MAX];
  memset(sources, 0, sizeof(struct sockaddr_in6) * RECV_MAX);
  memset(control_buf, 0, controllen * RECV_MAX);

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
      roughtime_result_t res;
      uint32_t offset, len;
      /* Ignore non-compliant packets and receive timeouts. */
      if (msgvec[i].msg_len < MAX_RESPONSE_LEN
          || (res = parse_roughtime_header(buf + i * MAX_RECV_LEN, msgvec[i].msg_len, &header))
              != ROUGHTIME_SUCCESS
          || (res = get_header_tag(&header, str_to_tag("NONC"), &offset, &len))
              != ROUGHTIME_SUCCESS
          || len != 64) {
        if (msgvec[i].msg_len > 0) {
          badcount += 1;
        }
        continue;
      }
      memcpy(&queries[num_queries].nonc, buf + offset + i * MAX_RECV_LEN, 64);
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

  /* Signal all threads and wait for them to quit. */
  for (long i = 0; i < num_response_threads; i++) {
    pthread_cond_signal(&arguments[i].queue_cond);
  }
  for (long i = 0; i < num_response_threads; i++) {
    pthread_join(threads[i], NULL);
    pthread_mutex_destroy(&arguments[i].queue_mutex);
    pthread_cond_destroy(&arguments[i].queue_cond);
  }

  printf("Quitting.\n");

  RETURN_CONF_STATS_PRIV_SOCK_ARGS(0);
}

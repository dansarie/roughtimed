/* test-roughtime.c
   Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se> */

#include "roughtime-common.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

bool quit = false;

void signal_handler(int signal) {
  quit = true;
}

int main(int argc, char *argv[]) {

  if (argc != 3) {
    printf("Usage: %s host port\n", argv[0]);
    return 1;
  }

  uint32_t nonc[16];
  uint32_t pad[158];
  uint8_t packet[844];
  uint32_t size = 832;
  uint32_t ver = 0x80000003;
  memset(pad, 0, 632);
  if (create_roughtime_packet(packet + 12, &size, 3,
      "PAD", 740, pad,
      "VER", 4, &ver,
      "NONC", 64, nonc
      ) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Fail!\n");
    return 1;
  }
  uint64_t roughtim = 0x4d49544847554f52;
  memcpy(packet, &roughtim, 8);
  memcpy(packet + 8, &size, 4);

  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_ADDRCONFIG;
  struct addrinfo *res = 0;
  int ret = getaddrinfo(argv[1], argv[2], &hints, &res);
  if (ret != 0) {
    printf("Address lookup failed: %s\n", gai_strerror(ret));
    return 1;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock == -1) {
    fprintf(stderr, "Error when creating socket: %s\n", strerror(errno));
    return 1;
  }

  if (signal(SIGINT, signal_handler) == SIG_ERR
      || signal(SIGTERM, signal_handler) == SIG_ERR) {
    fprintf(stderr, "Error when registering signal handler: %s\n", strerror(errno));
    return 1;
  }

  while (!quit) {
    sendto(sock, packet, size + 12, MSG_DONTWAIT, res->ai_addr, res->ai_addrlen);
  }

  return 0;
}

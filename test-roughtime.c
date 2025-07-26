/* test-roughtime.c

   Copyright (C) 2019-2025 Marcus Dansarie <marcus@dansarie.se>

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

#include "roughtime-common.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PACKET_SIZE (844)
#define ROUGHTIME_VERSION 0x8000000C

bool quit = false;

void signal_handler(int signal) {
  (void)signal;
  quit = true;
}

uint64_t xorshift1024() {
  static bool init = false;
  static uint64_t rand[16];
  static int p = 0;
  if (!init) {
    FILE *rand_fp = fopen("/dev/urandom", "r");
    if (rand_fp == NULL) {
      fprintf(stderr, "Error opening /dev/urandom.\n");
    } else if (fread(rand, 16 * sizeof(uint64_t), 1, rand_fp) != 1) {
      fprintf(stderr, "Error reading from /dev/urandom.\n");
      fclose(rand_fp);
    } else {
      init = true;
      fclose(rand_fp);
    }
  }
  uint64_t r0 = rand[p];
  p = (p + 1) & 15;
  uint64_t r1 = rand[p];
  r1 ^= r1 << 31;
  rand[p] = r1 ^ r0 ^ (r1 >> 11) ^ (r0 >> 30);
  return rand[p] * 1181783497276652981U;
}

int main(int argc, char *argv[]) {

  const char *host = NULL;
  const char *port = NULL;
  bool tcp = false;
  if (argc == 3) {
    host = argv[1];
    port = argv[2];
  } else if (argc == 4 && strcmp("-t", argv[1]) == 0) {
    host = argv[2];
    port = argv[3];
    tcp = true;
  } else {
    printf("Usage: %s [-t] host port\n", argv[0]);
    return 1;
  }

  uint8_t packet[PACKET_SIZE] = {0};
  uint8_t nonc[32] = {0};
  uint8_t pad[PACKET_SIZE - 104] = {0};
  uint32_t size = PACKET_SIZE - 12;
  uint32_t ver = htole32(ROUGHTIME_VERSION);
  if (create_roughtime_packet(packet + 12, &size, 3,
      "PAD", 740, pad,
      "VER", 4, &ver,
      "NONC", 32, nonc
      ) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Fail!\n");
    return 1;
  }

  roughtime_header_t header;
  uint32_t nonc_offset, nonc_len;
  if (parse_roughtime_header(packet + 12, size, &header) != ROUGHTIME_SUCCESS
      || get_header_tag(&header, str_to_tag("NONC"), &nonc_offset, &nonc_len)
          != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Fail!\n");
    return 1;
  }
  nonc_offset += 12;

  /* Create packet header. */
  *((uint64_t*)packet) = htole64(0x4d49544847554f52);
  *((uint32_t*)(packet + 8)) = htole32(size);
  size += 12;

  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_ADDRCONFIG;
  struct addrinfo *res = 0;
  int ret = getaddrinfo(host, port, &hints, &res);
  if (ret != 0) {
    printf("Address lookup failed: %s\n", gai_strerror(ret));
    return 1;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock == -1) {
    fprintf(stderr, "Error when creating socket: %s\n", strerror(errno));
    return 1;
  }
  if (tcp) {
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
      fprintf(stderr, "Connection error: %s\n", strerror(errno));
      close(sock);
      return 1;
    }
  }

  if (signal(SIGINT, signal_handler) == SIG_ERR
      || signal(SIGTERM, signal_handler) == SIG_ERR) {
    fprintf(stderr, "Error when registering signal handler: %s\n", strerror(errno));
    close(sock);
    return 1;
  }

  uint64_t num = 0;
  while (!quit) {
    for (int i = 0; i < 4; i++) {
      uint64_t rand = xorshift1024();
      memcpy(packet + nonc_offset + i * sizeof(uint64_t), &rand, sizeof(uint64_t));
    }
    if (tcp) {
      if (num < 1000000 && write(sock, packet, size) != size && errno != EAGAIN) {
        fprintf(stderr, "Error when writing to socket: %s\n", strerror(errno));
        close(sock);
        return 1;
      } else {
        num += 1;
      }
      int bytes = 0;
      while (ioctl(sock, FIONREAD, &bytes) == 0 && bytes > 0) {
        uint8_t buf[1000000];
        ssize_t r = read(sock, buf, 1000000);
        printf("Read %zd bytes. (%" PRIu64 ")\n", r, num);
      }
    } else {
      sendto(sock, packet, size, MSG_DONTWAIT, res->ai_addr, res->ai_addrlen);
    }
  }

  close(sock);
  return 0;
}

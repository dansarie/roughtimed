/* roughtime-common.h

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

#ifndef __ROUGHTIME_COMMON_H__
#define __ROUGHTIME_COMMON_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* Ceiling division: ceil(N/D). */
#define CEIL_DIV(N, D) (((N) + (D) - 1) / (D))

/* If C is true, the macro sets err = E, jumps to the function's error label, and prints the
   specified error message.
   C - conditional, jump to error if true.
   E - return value/error code. A member of sentinel_result_t.
   M - a string with an error message. */
#define RETURN_IF(C, E, M)\
if (C) {\
  fprintf(stderr, M);\
  fprintf(stderr, "\n");\
  err = E;\
  goto error;\
}

/* If E is not ROUGHTIME_SUCCESS, the macro sets err = E, jumps to the function's error label, and
   prints the specified error message to stderr.
   E - return_value/error code. A member of roughtime_result_t.
   M - a string with an error message. */
#define RETURN_ON_ERROR(E, M)\
{\
  roughtime_result_t e = E;\
  if (e != ROUGHTIME_SUCCESS) {\
    err = e;\
    fprintf(stderr, M);\
    goto error;\
  }\
}

typedef enum {
  ROUGHTIME_SUCCESS = 0,
  ROUGHTIME_BAD_ARGUMENT,
  ROUGHTIME_FORMAT_ERROR,
  ROUGHTIME_INTERNAL_ERROR,
  ROUGHTIME_QUEUE_FULL,
  ROUGHTIME_FILE_ERROR,
  ROUGHTIME_BAD_SIGNATURE,
  ROUGHTIME_NOT_FOUND,
  ROUGHTIME_MEMORY_ERROR
} roughtime_result_t;

#define ROUGHTIME_HEADER_MAX_TAGS 20

typedef struct {
  uint32_t offsets[ROUGHTIME_HEADER_MAX_TAGS];
  uint32_t lengths[ROUGHTIME_HEADER_MAX_TAGS];
  uint32_t tags[ROUGHTIME_HEADER_MAX_TAGS];
  uint32_t num_tags;
} roughtime_header_t;

/* Roughtime context for signing delegation certificates. */
extern const uint32_t SIGNED_RESPONSE_CONTEXT_LEN;
extern const uint32_t CERTIFICATE_CONTEXT_LEN;
/* Roughtime context for signing responses. */
extern const uint8_t *const CERTIFICATE_CONTEXT;
extern const uint8_t *const SIGNED_RESPONSE_CONTEXT;

/* Trims whitespace (as defined by isspace) from the ends of str. */
void trim(char *str);

/* Converts a string to a Roughtime tag. */
uint32_t str_to_tag(const char *str);

/* Creates a Roughtime packet from a number of tags. Returns ROUGHTIME_SUCCESS when successful.
   packet      An output buffer.
   size        Should contain the size (in bytes) of the packet buffer when called. Contains the
               size (in bytes) of the generated packet on return.
   num_tags    Number of tags in the packet.

   Three varargs for each tag:
   tag         A string with the tag name. Tags must be sorted by numeric value.
   field_size  Size (in bytes) of the tag data as a uint32_t. Must be divisible by 4.
   ptr         A pointer to the tag data. */
roughtime_result_t create_roughtime_packet(uint8_t *restrict packet, uint32_t *restrict size,
    uint32_t num_tags, ...);

/* Parse the header of a Roughtime packet. Returns ROUGHTIME_SUCCESS when successful.
   packet      A buffer containing a Roughtime packet.
   packet_len  The length (in bytes) of the packet.
   header      A pointer to a roughtime_header_t where the parsed header will be stored. */
roughtime_result_t parse_roughtime_header(const uint8_t *restrict packet, uint32_t packet_len,
    roughtime_header_t *restrict header);

/* Gets a tag's data offset and length from a roughtime_header_t.
   Returns ROUGHTIME_SUCCESS when successful and ROUGHTIME_NOT_FOUND if the header does not contain
   the tag.
   header  A roughtime_header_t filled by parse_roughtime_header.
   tag     A Roughtime tag. May be generated with str_to_tag.
   offset  Where the tag's data offset (in bytes) will be returned.
   length  Where the tag's data length (in bytes) will be returned. */
roughtime_result_t get_header_tag(const roughtime_header_t *restrict header,
    uint32_t tag, uint32_t *restrict offset, uint32_t *restrict length);

/* Parses a Roughtime timestamp. Returns ROUGHTIME_SUCCESS when successful.
   timestamp    A Roughtime timestamp.
   year         Return variable for the year.
   month        Return variable for the month.
   day          Return variable for the day.
   hour         Return variable for the hour.
   minute       Return variable for the minute.
   second       Return variable for the second. */
roughtime_result_t timestamp_to_time(time_t timestamp, uint32_t *restrict year,
    uint32_t *restrict month, uint32_t *restrict day, uint32_t *restrict hour,
    uint32_t *restrict minute, uint32_t *restrict second);

/* Attempts to verify an ed25519 signature. Returns ROUGHTIME_SUCCESS when successful and
   ROUGHTIME_BAD_SIGNATURE if the signature is not valid.
   data         A buffer containing the signed data.
   len          The length of the data buffer.
   context      A buffer containing a signing context that will be prepended to data before
                verification.
   context_len  The length of the context buffer.
   signature    The 64 byte signature to verify.
   public_key   The public key that supposedly generated the signature. */
roughtime_result_t verify_signature(const uint8_t *restrict data, uint32_t len,
    const uint8_t *restrict context, uint32_t context_len,
    const uint8_t *restrict signature, const uint8_t *restrict public_key);

/* Generates an ed25519 signature. Returns ROUGHTIME_SUCCESS when successful.
   data         A buffer containing the data to be signed.
   len          The length of the data buffer.
   context      A buffer containing a signing context that will be prepended to data before signing.
   context_len  The length of the context buffer.
   signature    Output buffer for the 64 byte signature.
   private_key  The private key should be used to generate the signature. */
roughtime_result_t sign(const uint8_t *restrict data, uint32_t len,
    const uint8_t *restrict context, uint32_t context_len,
    uint8_t *restrict signature, const uint8_t *restrict private_key);

/* Converts a base64 encoded string to raw bytes. Returns ROUGHTIME_SUCCESS when successful.
   base64   A null terminated base64 encoded string.
   out      An output buffer. Must have a size of at least 3 * b64len / 4 bytes, where b64len
            is the number of characters in base64, excluding whitespace.
   len_out  The size of the output buffer. */
roughtime_result_t from_base64(const uint8_t *restrict base64, uint8_t *restrict out,
    size_t *restrict len_out);

roughtime_result_t test_cert(const uint8_t *restrict publ, const uint8_t *restrict cert,
    bool verbose);

#endif /* __ROUGHTIME_COMMON_H__ */

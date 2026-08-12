/* roughtime_common.h

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

#ifndef __ROUGHTIME_COMMON_H__
#define __ROUGHTIME_COMMON_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/**
 * Ceiling division: ceil(N/D).
 * @param N numerator.
 * @param D denominator.
 */
#define CEIL_DIV(N, D) (((N) + (D) - 1) / (D))

/**
 * If C is true, the macro sets err = E, jumps to the function's error label, and prints the
 * specified error message.
 * @param C conditional, jump to error if true.
 * @param E return value/error code. A member of sentinel_result_t.
 * @param M a string with an error message.
 */
#define RETURN_IF(C, E, M)\
if (C) {\
  fprintf(stderr, "%s\n", (M));\
  err = (E);\
  goto error;\
}

/**
 * If E is not ROUGHTIME_SUCCESS, the macro sets err = E, jumps to the function's error label, and
 * prints the specified error message to stderr.
 * @param E return_value/error code. A member of roughtime_result_t.
 * @param M a string with an error message.
 */
#define RETURN_ON_ERROR(E, M)\
{\
  roughtime_result_t e = (E);\
  if (e != ROUGHTIME_SUCCESS) {\
    err = e;\
    fprintf(stderr, "%s\n", (M));\
    goto error;\
  }\
}

/** Represents the result of a function. Used to indicate success or failure. */
typedef enum {
  ROUGHTIME_SUCCESS = 0,    /**< The function returned successfully. */
  ROUGHTIME_BAD_ARGUMENT,   /**< A bad argument was supplied to the function. */
  ROUGHTIME_FORMAT_ERROR,   /**< The format of the parsed data was wrong. */
  ROUGHTIME_INTERNAL_ERROR, /**< An internal error or bug prevented successful execution. */
  ROUGHTIME_QUEUE_FULL,     /**< Data could not be added because a queue was full. */
  ROUGHTIME_FILE_ERROR,     /**< File access error. */
  ROUGHTIME_BAD_SIGNATURE,  /**< A signature failed validation. */
  ROUGHTIME_NOT_FOUND,      /**< The requested resource was not found. */
  ROUGHTIME_MEMORY_ERROR    /**< Error when allocating memory. */
} roughtime_result_t;

#define ROUGHTIME_HEADER_MAX_TAGS 20

/**
 * Represents the contents of a parsed Roughtime message header.
 */
typedef struct {
  uint32_t offsets[ROUGHTIME_HEADER_MAX_TAGS]; /**< Offset of the tag's value. */
  uint32_t lengths[ROUGHTIME_HEADER_MAX_TAGS]; /**< Length of the tag's value. */
  uint32_t tags[ROUGHTIME_HEADER_MAX_TAGS];    /**< Roughtime tag. */
  uint32_t num_tags;                           /**< Number of tags in the message. */
} roughtime_header_t;

/** Roughtime context for signing delegation certificates. */
extern const uint8_t *const CERTIFICATE_CONTEXT;
/** Roughtime context for signing responses. */
extern const uint8_t *const SIGNED_RESPONSE_CONTEXT;
/** Length, in bytes, of the context for signing delegation certificates. */
extern const uint32_t CERTIFICATE_CONTEXT_LEN;
/** Length, in bytes, of the context for signing responses. */
extern const uint32_t SIGNED_RESPONSE_CONTEXT_LEN;

/**
 * Trims whitespace (as defined by isspace) from the ends of str.
 * @param str the string to trim. It will be trimmed in place.
 */
void trim(char *str);

/**
 * Converts a string to a Roughtime tag. No validity checks are performed.
 * @param str a zero-terminated string of up to four characters.
 * @return the string's tag value.
 */
uint32_t str_to_tag(const char *str);

/** Creates a Roughtime message from a number of tags. Returns ROUGHTIME_SUCCESS when successful.
 * @param message an output buffer.
 * @param size should contain the size (in bytes) of the message buffer when called. Contains the
 * size (in bytes) of the generated message on return.
 * @param num_tags number of tags in the message.
 * @param ... three varargs are included for each tag indicated by the num_tags parameter. Tags must
 * be sorted by numeric value. 1. A zero-terminated string with the tag name. 2. A field size (in
 * bytes) of the tag data as a uint32_t. The field size must be divisible by 4. 3. A pointer to the
 * tag data.
 */
roughtime_result_t create_roughtime_message(
    uint8_t *restrict message,
    uint32_t *restrict size,
    uint32_t num_tags,
    ...);

/**
 * Parses the header of a Roughtime message.
 * @param message a buffer containing a Roughtime message.
 * @param message_len the length (in bytes) of the message.
 * @param header a pointer to a roughtime_header_t where the parsed header will be stored.
 */
roughtime_result_t parse_roughtime_header(
    const uint8_t *restrict message,
    uint32_t message_len,
    roughtime_header_t *restrict header);

/**
 * Gets a tag's data offset and length from a roughtime_header_t.
 * @param header a roughtime_header_t filled by parse_roughtime_header.
 * @param tag a Roughtime tag. May be generated with str_to_tag.
 * @param offset a return pointer for the tag's data offset (in bytes).
 * @param length a return pointer for the tag's data length (in bytes).
 * @return ROUGHTIME_SUCCESS when successful and ROUGHTIME_NOT_FOUND if the header does not contain
 * the tag.
 */
roughtime_result_t get_header_tag(
    const roughtime_header_t *restrict header,
    uint32_t tag,
    uint32_t *restrict offset,
    uint32_t *restrict length);

/**
 * Parses a Roughtime timestamp.
 * @param timestamp a Roughtime timestamp.
 * @param year return pointer for the year.
 * @param month return pointer for the month.
 * @param day return pointer for the day.
 * @param hour return pointer for the hour.
 * @param minute return pointer for the minute.
 * @param second return pointer for the second.
 */
roughtime_result_t timestamp_to_time(
    time_t timestamp,
    uint32_t *restrict year,
    uint32_t *restrict month,
    uint32_t *restrict day,
    uint32_t *restrict hour,
    uint32_t *restrict minute,
    uint32_t *restrict second);

/**
 * Attempts to verify an ed25519 signature.
 * @param data a buffer containing the signed data.
 * @param len the length of the data buffer.
 * @param context a buffer containing a signing context that will be prepended to data before
 * verification.
 * @param context_len length of the context buffer.
 * @param signature the 64 byte signature to verify.
 * @param public_key the public key that supposedly generated the signature.
 * @return ROUGHTIME_SUCCESS when successful and ROUGHTIME_BAD_SIGNATURE if the signature is not
 * valid.
 */
roughtime_result_t verify_signature(
    const uint8_t *restrict data,
    uint32_t len,
    const uint8_t *restrict context,
    uint32_t context_len,
    const uint8_t *restrict signature,
    const uint8_t *restrict public_key);

/**
 * Generates an ed25519 signature.
 * @param data a buffer containing the data to be signed.
 * @param len length of the data buffer.
 * @param context a buffer containing a signing context that will be prepended to data before
 * signing.
 * @param context_len length of the context buffer.
 * @param signature output buffer for the 64 byte signature.
 * @param private_key the private key should be used to generate the signature.
 */
roughtime_result_t sign(
    const uint8_t *restrict data,
    uint32_t len,
    const uint8_t *restrict context,
    uint32_t context_len,
    uint8_t *restrict signature,
    const uint8_t *restrict private_key);

/**
 * Creates the public key associated with a private ed25519 key.
 * @param priv a 32 byte (256 bit) private ed25519 key.
 * @param publ a 32 byte array where the generated public key will be returned.
 */
roughtime_result_t priv_to_publ(const uint8_t *restrict priv, uint8_t *restrict publ);

/**
 * Converts a base64 encoded string to raw bytes.
 * @param base64 a null terminated base64 encoded string.
 * @param out on output buffer. The buffer ust have a size of at least 3 * b64len / 4 bytes, where
 * b64len is the number of characters in base64, excluding whitespace.
 * @param len_out size of the output buffer.
 */
roughtime_result_t from_base64(
    const uint8_t *restrict base64,
    uint8_t *restrict out,
    size_t *restrict len_out);

/**
 * Tests if a certificate has a valid signature.
 * @param publ a 32 byte Ed25519 public key.
 * @param cert a 152 byte CERT message.
 * @param verbose when true, information about the certificate and result of te test is printed to
 *          standard out.
 * @return ROUGHTIME_SUCCESS when the signature is valid and ROUGHTIME_BAD_SIGNATURE if it is not.
 */
roughtime_result_t test_cert(
    const uint8_t *restrict publ,
    const uint8_t *restrict cert,
    bool verbose);

#endif /* __ROUGHTIME_COMMON_H__ */

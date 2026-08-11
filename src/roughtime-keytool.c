/* roughtimed-keytool.c

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

#include <endian.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "roughtime_common.h"

#define KEYLEN 32
#define BASE64LEN 44

/**
 * Prints a help message to the console.
 * @param filename the application executable filename, typically argv[0].
 */
void printhelp(const char *filename) {
  printf("Usage:\n");
  printf("  %s key  -- generate ed25519 keypair.\n", filename);
  printf("  %s pub  -- calculate public key from a private key.\n", filename);
  printf("  %s dele -- generate delegate certificate.\n", filename);
  printf("  %s cert -- parse a base64 encoded CERT message.\n", filename);
  printf("\n");
}

/**
 * Creates the public key associated with a private ed25519 key.
 * @param priv a 32 byte (256 bit) private ed25519 key.
 * @param publ a 32 byte array where the generated public key will be returned.
 */
roughtime_result_t priv_to_publ(const uint8_t *restrict priv, uint8_t *restrict publ) {
  if (priv == NULL || publ == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, KEYLEN);
  size_t keylen = KEYLEN;
  if (pkey == NULL || EVP_PKEY_get_raw_public_key(pkey, publ, &keylen) != 1) {
    EVP_PKEY_free(pkey);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  EVP_PKEY_free(pkey);
  if (keylen != KEYLEN) {
    return ROUGHTIME_INTERNAL_ERROR;
  }
  return ROUGHTIME_SUCCESS;
}

/**
 * Removes all newline characters ('\n') from a string.
 * @param str a string. The newlines are removed in place.
 */
roughtime_result_t remove_newlines(uint8_t *str) {
  if (str == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  size_t p = 0;
  while (str[p] != '\0') {
    if (str[p] == '\n') {
      memmove(str + p, str + p + 1, strlen((char *)(str + p)) + 1);
    } else {
      p += 1;
    }
  }
  return ROUGHTIME_SUCCESS;
}

/**
 * Converts a byte array to base64 format.
 * @param in the array to convert.
 * @param len_in the array length, in bytes.
 * @param base64 the buffer that will hold the generated, null terminated, base64 string.
 * @param len_base64 size of the base64 output buffer. Must be at least
 * floor(len_in / 48) * 65 + ceil((len_in mod 48) / 3) * 4 + 2.
 */
roughtime_result_t to_base64(
    const uint8_t *restrict in,
    size_t len_in,
    uint8_t *restrict base64,
    size_t len_base64) {
  if (in == NULL || base64 == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  size_t req_len = (len_in / 48) * 65 + 1;
  if (len_in % 48 != 0) {
    req_len += CEIL_DIV(len_in % 48, 3) * 4 + 1;
  }
  if (req_len > len_base64) {
    fprintf(stderr, "Output buffer too small for input.\n");
    return ROUGHTIME_BAD_ARGUMENT;
  }
  EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "Error allocating base64 context.\n");
    return ROUGHTIME_INTERNAL_ERROR;
  }
  EVP_EncodeInit(ctx);
  int outl = 0;
  if (!EVP_EncodeUpdate(ctx, base64, &outl, in, len_in)) {
    EVP_ENCODE_CTX_free(ctx);
    fprintf(stderr, "Error when base64 encoding data.\n");
    explicit_bzero(base64, len_base64);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  EVP_EncodeFinal(ctx, base64 + outl, &outl);
  EVP_ENCODE_CTX_free(ctx);
  return remove_newlines(base64);
}

/**
 * Converts a 32 byte key to base64 format.
 * @param key a 32 byte (256 bit) key.
 * @param base64 an outbut buffer, at least 46 bytes large.
 */
roughtime_result_t key_to_base64(const uint8_t *restrict key, uint8_t *restrict base64) {
  return to_base64(key, KEYLEN, base64, BASE64LEN + 2);
}

/**
 * Parses a base64 encoded key.
 * @param base64 a base64-encoded 32 byte key.
 * @param key 32 byte array that will hold the parsed key.
 */
roughtime_result_t base64_to_key(const uint8_t *restrict base64, uint8_t *restrict key) {
  size_t keylen = KEYLEN + 1;
  roughtime_result_t res;
  if ((res = from_base64(base64, key, &keylen)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(key, KEYLEN);
    return res;
  }
  if (keylen != KEYLEN) {
    explicit_bzero(key, KEYLEN);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  return ROUGHTIME_SUCCESS;
}

/**
 * Gets a line from stdin.
 * @param line an output buffer.
 * @param len the size of the output buffer.
 */
roughtime_result_t get_line_stdin(uint8_t *line, size_t len) {
  uint8_t *lineptr = NULL;
  size_t linelen = 0;
  if (getline((char**)&lineptr, &linelen, stdin) < 0) {
    free(lineptr);
    fprintf(stderr, "Error when getting line from stdin.\n");
    return ROUGHTIME_INTERNAL_ERROR;
  }
  roughtime_result_t res;
  if ((res = remove_newlines(lineptr)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(lineptr, linelen);
    free(lineptr);
    return res;
  }
  if (strlen((char*)lineptr) > len - 1) {
    explicit_bzero(lineptr, linelen);
    free(lineptr);
    fprintf(stderr, "Input line too long.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  strcpy((char*)line, (char*)lineptr);
  explicit_bzero(lineptr, linelen);
  free(lineptr);
  return ROUGHTIME_SUCCESS;
}

/**
 * Prompts the user to input a base64 encoded key, gets it from stdin and parses it.
 * @param prompt a zero-terminated string with the text to prompt the user with.
 * @param key a 32 byte buffer that will hold the parsed key.
 */
roughtime_result_t get_key(const char *restrict prompt, uint8_t *restrict key) {
  if (prompt == NULL || key == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  printf("%s ", prompt);
  fflush(stdout);
  uint8_t base64[BASE64LEN + 1];
  roughtime_result_t res;
  if ((res = get_line_stdin(base64, BASE64LEN + 1)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(base64, BASE64LEN + 1);
    return res;
  }
  if ((res = base64_to_key(base64, key)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(base64, BASE64LEN + 1);
    explicit_bzero(key, 32);
    return res;
  }
  explicit_bzero(base64, BASE64LEN + 1);
  return ROUGHTIME_SUCCESS;
}

/**
 * Validates a date between 2001-01-01 and 2099-12-31. Optionally returns the day of year (Julian
 * date).
 * @param year a year (2001-2099).
 * @param month a month (1-12).
 * @param day a day (1-31).
 * @param yday pointer to a variable that will hold the day of year (1 January = 1) of the date.
 * May be NULL.
 */
bool validate_date(int year, int month, int day, int *yday) {
  if (year <= 2000 || year >= 2100) {
    return false;
  }
  if (month < 1 || month > 12) {
    return false;
  }
  int days[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (year % 4 == 0) {
    days[2] = 29;
  }
  if (day < 1 || day > days[month]) {
    return false;
  }
  if (yday != NULL) {
    *yday = 0;
    for (int i = 0; i < month; i++) {
      *yday += days[i];
    }
    *yday += day;
  }
  return true;
}

/**
 * Prompts the user to enter a date, gets a date in the format YYYY-MM-DD from stdin, validates it
 * and returns year, month, and day.
 * @param timestamp UNIX timestamp representation of the first second of the date entered by the
 * user.
 * @param prompt a zero-terminated string with prompt to display when getting the date.
 */
roughtime_result_t get_date(time_t *restrict timestamp, const char *restrict prompt) {
  if (timestamp == NULL || prompt == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  roughtime_result_t err = ROUGHTIME_SUCCESS;
  printf("%s", prompt);
  fflush(stdout);
  int pyear, pmonth, pday;
  if (scanf("%d-%d-%d", &pyear, &pmonth, &pday) != 3
      || !validate_date(pyear, pmonth, pday, NULL)) {
    fprintf(stderr, "Bad date format.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  struct tm date = {
    .tm_year = pyear - 1900,
    .tm_mon  = pmonth - 1,
    .tm_mday = pday
  };
  time_t ts = timegm(&date);
  RETURN_IF(ts < 0, ROUGHTIME_INTERNAL_ERROR, "timegm returned an error.");
  *timestamp = ts;
error:
  return err;
}

/**
 * Prompts the user to input a base64 encoded CERT message, gets it from stdin and parses it.
 * @param cert a 152 byte buffer that will hold the parsed key
 */
roughtime_result_t get_cert(uint8_t *cert) {
  printf("Enter CERT message: ");
  fflush(stdout);
  uint8_t base64[205];
  roughtime_result_t res;
  if ((res = get_line_stdin(base64, 205)) != ROUGHTIME_SUCCESS) {
    return res;
  }
  size_t len = 153;
  uint8_t buf[153];
  if ((res = from_base64(base64, (uint8_t*)buf, &len)) != ROUGHTIME_SUCCESS) {
    return res;
  }
  if (len != 152) {
    fprintf(stderr, "Bad CERT message size: %zu.\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  memcpy(cert, buf, 152);
  return ROUGHTIME_SUCCESS;
}

/**
 * Prompts the user for a long-term public key and a certificate. It then validates the certificate,
 * writing the results to standard out.
 */
roughtime_result_t parsecert(void) {
  uint8_t publ[32];
  uint8_t cert[152];
  roughtime_header_t header;
  roughtime_result_t err = ROUGHTIME_SUCCESS;
  RETURN_ON_ERROR(get_key("Enter long-term public key:", publ), "Error when getting key.");
  RETURN_ON_ERROR(get_cert(cert), "Error when getting certificate.");

  RETURN_ON_ERROR(parse_roughtime_header(cert, 152, &header), "Error when parsing CERT header.");

  RETURN_ON_ERROR(test_cert(publ, cert, true), "Error when testing certificate.");

error:
  return err;
}

/**
 * Lets the user generate a delegate key certificate.
 */
roughtime_result_t gendele(void) {
  uint8_t priv[KEYLEN];
  time_t ts1, ts2;
  roughtime_result_t res;
  /* Prompt user for private long-term key and validity time. */
  if ((res = get_key("Enter long-term private key:", priv)) != ROUGHTIME_SUCCESS
      || (res = get_date(&ts1, "Enter start date (YYYY-MM-DD): ")) != ROUGHTIME_SUCCESS
      || (res = get_date(&ts2, "  Enter end date (YYYY-MM-DD): ")) != ROUGHTIME_SUCCESS) {
    explicit_bzero(priv, KEYLEN);
    return res;
  }
  if (ts1 >= ts2) {
    fprintf(stderr, "End date must be after start date.\n");
    explicit_bzero(priv, KEYLEN);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint64_t mint = htole64((uint64_t)ts1);
  uint64_t maxt = htole64((uint64_t)ts2);

  /* Generate a delegate private key. */
  uint8_t dele_priv[KEYLEN];
  if (RAND_priv_bytes(dele_priv, KEYLEN) != 1) {
    fprintf(stderr, "Could not generate 32 random bytes for private key.\n");
    explicit_bzero(priv, KEYLEN);
    explicit_bzero(dele_priv, KEYLEN);
    return ROUGHTIME_INTERNAL_ERROR;
  }

  /* Calculate delegate public key. */
  uint8_t dele_publ[KEYLEN];
  if ((res = priv_to_publ(dele_priv, dele_publ)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when calculating public key.\n");
    explicit_bzero(priv, KEYLEN);
    explicit_bzero(dele_priv, KEYLEN);
    return res;
  }

  /* Generate the DELE message. */
  uint8_t dele_message[72];
  uint32_t message_size = 72;
  if ((res = create_roughtime_message(
      dele_message,
      &message_size,
      3,
      "PUBK", 32, dele_publ,
      "MINT", 8, &mint,
      "MAXT", 8, &maxt)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when creating DELE message.\n");
    explicit_bzero(priv, KEYLEN);
    explicit_bzero(dele_priv, KEYLEN);
    return res;
  }

  /* Sign DELE message. */
  uint8_t sig[64];
  sign((uint8_t*)dele_message, 72, CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT_LEN, sig, priv);

  /* Create CERT message. */
  uint8_t cert_message[152];
  message_size = 152;
  if ((res = create_roughtime_message(
      cert_message,
      &message_size,
      2,
      "SIG", 64, sig,
      "DELE", 72, dele_message)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when creating CERT message.\n");
    explicit_bzero(dele_priv, KEYLEN);
    explicit_bzero(cert_message, 152);
    return res;
  }

  /* Convert delegate private key and CERT message to base64. */
  uint8_t b64dele_priv[BASE64LEN + 2];
  if ((res = key_to_base64(dele_priv, b64dele_priv)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when performing base64 encoding.\n");
    explicit_bzero(dele_priv, KEYLEN);
    explicit_bzero(cert_message, 152);
    explicit_bzero(b64dele_priv, BASE64LEN + 2);
    return res;
  }
  explicit_bzero(dele_priv, KEYLEN);
  uint8_t b64cert[209];
  if ((res = to_base64((uint8_t*)cert_message, sizeof(uint32_t) * 38, b64cert, 209))
      != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when performing base64 encoding.\n");
    explicit_bzero(b64dele_priv, BASE64LEN + 2);
    explicit_bzero(cert_message, 152);
    explicit_bzero(b64cert, 209);
    return res;
  }
  printf("\nDelegate private key: %s\n", b64dele_priv);
  printf("CERT message: %s\n", b64cert);
  explicit_bzero(b64dele_priv, BASE64LEN + 2);
  explicit_bzero(cert_message, 152);
  explicit_bzero(b64cert, 209);
  return ROUGHTIME_SUCCESS;
}

/**
 * Lets the user generate the public key from a private key.
 */
roughtime_result_t genpub(void) {
  uint8_t priv[KEYLEN];
  uint8_t publ[KEYLEN];
  uint8_t b64publ[BASE64LEN + 2];
  roughtime_result_t res;
  if ((res = get_key("Enter private key:", priv)) != ROUGHTIME_SUCCESS
      || (res = priv_to_publ(priv, publ)) != ROUGHTIME_SUCCESS
      || (res = key_to_base64(publ, b64publ)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(priv, KEYLEN);
    return res;
  }
  explicit_bzero(priv, KEYLEN);
  printf("Public key: %s\n", b64publ);
  return ROUGHTIME_SUCCESS;
}

/**
 * Generates a ed25519 keypair and prints it to standard out.
 */
roughtime_result_t keygen(void) {
  uint8_t priv[KEYLEN];
  if (RAND_priv_bytes(priv, KEYLEN) != 1) {
    fprintf(stderr, "Could not generate 32 random bytes for private key.\n");
    explicit_bzero(priv, KEYLEN);
    return ROUGHTIME_INTERNAL_ERROR;
  }
  uint8_t publ[KEYLEN];
  roughtime_result_t res;
  if ((res = priv_to_publ(priv, publ)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when generating public key.\n");
    explicit_bzero(priv, KEYLEN);
    return res;
  }
  uint8_t b64priv[BASE64LEN + 2];
  uint8_t b64publ[BASE64LEN + 2];
  if ((res = key_to_base64(priv, b64priv)) != ROUGHTIME_SUCCESS
      || (res = key_to_base64(publ, b64publ)) != ROUGHTIME_SUCCESS) {
    explicit_bzero(priv, KEYLEN);
    explicit_bzero(b64priv, BASE64LEN + 2);
    fprintf(stderr, "Error when performing base64 encoding.\n");
    return res;
  }
  explicit_bzero(priv, KEYLEN);
  printf("Private key: %s\n", b64priv);
  printf("Public key:  %s\n", b64publ);

  explicit_bzero(priv, KEYLEN);
  explicit_bzero(b64priv, BASE64LEN + 1);
  return 0;
}

/**
 * Keytool entry function.
 * @param argc number of arguments.
 * @param argv argument buffer.
 */
int main(int argc, char *argv[]) {
  if (argc != 2) {
    printhelp(argv[0]);
    return 1;
  } else if (strcmp("key", argv[1]) == 0) {
    return keygen() == ROUGHTIME_SUCCESS ? 0 : 1;
  } else if (strcmp("pub", argv[1]) == 0) {
    return genpub() == ROUGHTIME_SUCCESS ? 0 : 1;
  } else if (strcmp("dele", argv[1]) == 0) {
    return gendele() == ROUGHTIME_SUCCESS ? 0 : 1;
  } else if (strcmp("cert", argv[1]) == 0) {
    return parsecert() == ROUGHTIME_SUCCESS ? 0 : 1;
  } else {
    printhelp(argv[0]);
    return 1;
  }

  return 0;
}

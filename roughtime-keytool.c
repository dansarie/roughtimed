/* roughtimed-keytool.c

   Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se>

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

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEYLEN 32
#define BASE64LEN 44

/* Prints a help message to the console.
   filename - the application executable filename, typically argv[0]. */
void printhelp(const char *filename) {
  printf("Usage:\n");
  printf("  %s key  -- generate ed25519 keypair.\n", filename);
  printf("  %s pub  -- calculate public key from a private key.\n", filename);
  printf("  %s dele -- generate delegate certificate.\n", filename);
  printf("  %s cert -- parse a base64 encoded CERT packet.\n", filename);
  printf("\n");
}

/* Creates the public key associated with a private ed25519 key.
   priv - a 32 byte (256 bit) private ed25519 key.
   publ - a 32 byte array where the generated public key will be returned. */
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
  assert(keylen == KEYLEN);
  return ROUGHTIME_SUCCESS;
}

/* Removes all newline characters ('\n') from a string.
   str - a string. */
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

/* Converts a byte array to base64 format.
   in - the array to convert.
   len_in - the array length, in bytes.
   base64 - the buffer that will hold the generated, null terminated, base64 string.
   len_base64 - size of the base64 output buffer. Must be at least
       floor(len_in / 48) * 65 + ceil((len_in mod 48) / 3) * 4 + 2. */
roughtime_result_t to_base64(const uint8_t *restrict in, size_t len_in, uint8_t *restrict base64,
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

/* Converts a 32 byte key to base64 format.
   key - a 32 byte (256 bit) key.
   base64 - an outbut buffer, at least 46 bytes large. */
roughtime_result_t key_to_base64(const uint8_t *restrict key, uint8_t *restrict base64) {
  return to_base64(key, KEYLEN, base64, BASE64LEN + 2);
}

/* Parses a base64 encoded key.
   base64 - a base64 encoded 32 byte key.
   key - 32 byte array that will hold the parsed key. */
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

/* Gets a line from stdin.
   line - an output buffer.
   len - the size of the output buffer. */
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

/* Prompts the user to input a base64 encoded key, gets it from stdin and parses it.
   key - a 32 byte buffer that will hold the parsed key. */
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

/* Validates a date between 2001-01-01 and 2099-12-31. Optionally returns the day of year.
   year - a year (2001-2099).
   month - a month (1-12).
   day - a day (1-31).
   yday - pointer to a variable that will hold the day of year (1 January = 1) of the date.
       May be NULL. */
bool validate_date(int year, int month, int day, int *yday) {
  if (year <= 2000 || year >= 2100) {
    return false;
  }
  if (month < 1 || month > 12) {
    return false;
  }
  int days[] = {00, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
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

/* Prompts the user to enter a date, gets it from stdin, validates it and returns the corresponding
       modified julian date.
   mjd - will hold the modified julian date of the entered date. */
roughtime_result_t get_date(uint32_t *mjd, const char *prompt) {
  if (mjd == NULL || prompt == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  printf("%s", prompt);
  fflush(stdout);
  int year, month, day, yday;
  if (scanf("%d-%d-%d", &year, &month, &day) != 3
      || !validate_date(year, month, day, &yday)) {
    fprintf(stderr, "Bad date format.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  *mjd = 51544 + (year - 2000) * 365 + (year - 2001) / 4 + yday;
  return ROUGHTIME_SUCCESS;
}

/* Prompts the user to input a base64 encoded CERT packet, gets it from stdin and parses it.
   cert - a 152 byte buffer that will hold the parsed key */
roughtime_result_t get_cert(uint8_t *cert) {
  printf("Enter CERT packet: ");
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
    fprintf(stderr, "Bad CERT packet size: %zu.\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  memcpy(cert, buf, 152);
  return ROUGHTIME_SUCCESS;
}

roughtime_result_t parsecert() {
  uint8_t publ[32];
  uint8_t cert[152];
  roughtime_result_t res;
  if ((res = get_key("Enter long-term public key:", publ)) != ROUGHTIME_SUCCESS
      || (res = get_cert(cert)) != ROUGHTIME_SUCCESS) {
    return res;
  }

  roughtime_header_t header;
  if ((res = parse_roughtime_header(cert, 152, &header))
      != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when parsing CERT header.\n");
    return res;
  }

  if (header.num_tags != 2) {
    printf("Unexpected number of tags in CERT header: %" PRIu32 "\n", header.num_tags);
  }

  uint32_t offset, len;

  if ((res = get_header_tag(&header, str_to_tag("DELE"), &offset, &len)) != ROUGHTIME_SUCCESS) {
    printf("Missing DELE tag.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint8_t dele[len];
  memcpy(dele, cert + offset, len);

  if ((res = get_header_tag(&header, str_to_tag("SIG"), &offset, &len)) != ROUGHTIME_SUCCESS) {
    printf("Missing SIG tag.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  if (len != 64) {
    printf("Bad signature length: %" PRIu32 "\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint8_t sig[64];
  memcpy(sig, cert + offset, 64);

  if ((res = parse_roughtime_header(dele, 72, &header))
      != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when parsing DELE header.\n");
    return res;
  }

  if (header.num_tags != 3) {
    printf("Unexpected number of tags in DELE header: %" PRIu32 "\n", header.num_tags);
  }

  if ((res = get_header_tag(&header, str_to_tag("PUBK"), &offset, &len)) != ROUGHTIME_SUCCESS) {
    printf("Missing PUBK tag.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  if (len != 32) {
    printf("Bad public key length: %" PRIu32 "\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint8_t pubk[32];
  memcpy(pubk, dele + offset, 32);

  if ((res = get_header_tag(&header, str_to_tag("MINT"), &offset, &len)) != ROUGHTIME_SUCCESS) {
    printf("Missing MINT tag.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  if (len != 8) {
    printf("Bad MINT length: %" PRIu32 "\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint64_t mint = le64toh(*((uint64_t*)(dele + offset)));

  if ((res = get_header_tag(&header, str_to_tag("MAXT"), &offset, &len)) != ROUGHTIME_SUCCESS) {
    printf("Missing MAXT tag.\n");
    return ROUGHTIME_FORMAT_ERROR;
  }
  if (len != 8) {
    printf("Bad MAXT length: %" PRIu32 "\n", len);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint64_t maxt = le64toh(*((uint64_t*)(dele + offset)));

  uint8_t pubk_base64[46];
  key_to_base64(pubk, pubk_base64);
  uint32_t mjd, hour, minute, second, microsecond;
  timestamp_to_time(mint, &mjd, &hour, &minute, &second, &microsecond);
  printf("\nPUBK: %s\n", pubk_base64);
  printf("MINT: MJD: %" PRIu32 "  %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32 ".%06" PRIu32 " "
      "(%016" PRIx64 ")\n", mjd, hour, minute, second, microsecond, mint);
  timestamp_to_time(maxt, &mjd, &hour, &minute, &second, &microsecond);
  printf("MAXT: MJD: %" PRIu32 "  %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32 ".%06" PRIu32 " "
      "(%016" PRIx64 ")\n", mjd, hour, minute, second, microsecond, maxt);

  res = verify_signature(dele, 72, CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT_LEN, sig, publ);
  if (res == ROUGHTIME_SUCCESS) {
    printf("Good signature!\n");
  } else if (res == ROUGHTIME_BAD_SIGNATURE) {
    printf("BAD SIGNATURE!\n");
  } else {
    fprintf(stderr, "Internal error when verifying signature.\n");
  }

  return ROUGHTIME_SUCCESS;
}

/* Generate a delegate key certificate. */
roughtime_result_t gendele() {
  uint8_t priv[KEYLEN];
  uint32_t mjd1, mjd2;
  roughtime_result_t res;
  /* Prompt user for private long-term key and validity time. */
  if ((res = get_key("Enter long-term private key:", priv)) != ROUGHTIME_SUCCESS
      || (res = get_date(&mjd1, "Enter start date (YYYY-MM-DD): ")) != ROUGHTIME_SUCCESS
      || (res = get_date(&mjd2, "  Enter end date (YYYY-MM-DD): ")) != ROUGHTIME_SUCCESS) {
    explicit_bzero(priv, KEYLEN);
    return res;
  }
  if (mjd1 >= mjd2) {
    fprintf(stderr, "End date must be after start date.\n");
    explicit_bzero(priv, KEYLEN);
    return ROUGHTIME_FORMAT_ERROR;
  }
  uint64_t mint = htole64((uint64_t)mjd1 << 40);
  uint64_t maxt = htole64((uint64_t)mjd2 << 40);

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

  /* Generate the DELE packet. */
  uint8_t dele_packet[72];
  uint32_t packet_size = 72;
  if ((res = create_roughtime_packet(dele_packet, &packet_size, 3,
      "PUBK", 32, dele_publ,
      "MINT", 8, &mint,
      "MAXT", 8, &maxt)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when creating DELE packet.\n");
    explicit_bzero(priv, KEYLEN);
    explicit_bzero(dele_priv, KEYLEN);
    return res;
  }

  /* Sign DELE packet. */
  uint8_t sig[64];
  sign((uint8_t*)dele_packet, 72, CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT_LEN, sig, priv);

  /* Create CERT packet. */
  uint8_t cert_packet[152];
  packet_size = 152;
  if ((res = create_roughtime_packet(cert_packet, &packet_size, 2,
      "SIG", 64, sig,
      "DELE", 72, dele_packet)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when creating CERT packet.\n");
    explicit_bzero(dele_priv, KEYLEN);
    explicit_bzero(cert_packet, 152);
    return res;
  }

  /* Convert delegate private key and CERT packet to base64. */
  uint8_t b64dele_priv[BASE64LEN + 2];
  if ((res = key_to_base64(dele_priv, b64dele_priv)) != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when performing base64 encoding.\n");
    explicit_bzero(dele_priv, KEYLEN);
    explicit_bzero(cert_packet, 152);
    explicit_bzero(b64dele_priv, BASE64LEN + 2);
    return res;
  }
  explicit_bzero(dele_priv, KEYLEN);
  uint8_t b64cert[209];
  if ((res = to_base64((uint8_t*)cert_packet, sizeof(uint32_t) * 38, b64cert, 209))
      != ROUGHTIME_SUCCESS) {
    fprintf(stderr, "Error when performing base64 encoding.\n");
    explicit_bzero(b64dele_priv, BASE64LEN + 2);
    explicit_bzero(cert_packet, 152);
    explicit_bzero(b64cert, 209);
    return res;
  }
  printf("\nDelegate private key: %s\n", b64dele_priv);
  printf("CERT packet: %s\n", b64cert);
  explicit_bzero(b64dele_priv, BASE64LEN + 2);
  explicit_bzero(cert_packet, 152);
  explicit_bzero(b64cert, 209);
  return ROUGHTIME_SUCCESS;
}

/* Generate the public key for a private key. */
roughtime_result_t genpub() {
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

/* Generate an ed25519 keypair. */
roughtime_result_t keygen() {
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

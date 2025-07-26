/* config.c

   Copyright (C) 2019 Marcus Dansarie <marcus@dansarie.se>

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

#include "config.h"
#include "roughtime-common.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONFIG_ITEMS 100
#define MAX_CONFIG_STRING_SIZE 1000
typedef struct {
  char key[MAX_CONFIG_STRING_SIZE];
  char value[MAX_CONFIG_STRING_SIZE];
} roughtime_config_item_t;
roughtime_config_item_t configuration_items[MAX_CONFIG_ITEMS];
int num_config_items = 0;

roughtime_result_t read_config_file(const char *filename) {

  if (filename == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }

  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    return ROUGHTIME_FILE_ERROR;
  }

  char *line = NULL;
  size_t linelen = 0;

  while (getline(&line, &linelen, fp) >= 0 && num_config_items < MAX_CONFIG_ITEMS) {
    trim(line);
    if (strlen(line) == 0 || line[0] == '#') {
      continue;
    }
    size_t p = 0;
    while (!isspace(line[p]) && line[p] != '\0') {
      p++;
    }
    char *key = line;
    char *value;
    if (line[p] == '\0') {
      value = line + p;
    } else {
      line[p] = '\0';
      value = line + p + 1;
      trim(value);
    }
    if (strlen(key) > MAX_CONFIG_STRING_SIZE - 1 || strlen(value) > MAX_CONFIG_STRING_SIZE - 1) {
      continue;
    }
    size_t i;
    for (i = 0; key[i] != '\0'; i++) {
      configuration_items[num_config_items].key[i] = tolower(key[i]);
    }
    configuration_items[num_config_items].key[i] = '\0';
    strcpy(configuration_items[num_config_items].value, value);
    num_config_items += 1;
  }

  free(line);
  fclose(fp);

  return ROUGHTIME_SUCCESS;
}

roughtime_result_t get_config(const char *restrict key, const char **restrict value) {

  if (key == NULL || value == NULL) {
    return ROUGHTIME_BAD_ARGUMENT;
  }
  size_t keylen = strlen(key);
  char lc_key[keylen + 1];
  for (size_t i = 0; i < keylen; i++) {
    lc_key[i] = tolower(key[i]);
  }
  lc_key[keylen] = '\0';
  for (int i = 0; i < num_config_items; i++) {
    if (strcmp(configuration_items[i].key, lc_key) == 0) {
      *value = &configuration_items[i].value[0];
      return ROUGHTIME_SUCCESS;
    }
  }
  return ROUGHTIME_NOT_FOUND;
}

void clear_config() {
  explicit_bzero(configuration_items, sizeof(roughtime_config_item_t) * MAX_CONFIG_ITEMS);
}

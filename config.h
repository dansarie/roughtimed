/* config.h

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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "roughtime-common.h"

/**
 * Replaces the current global configuration state with a configuration read from a file.
 * @param filename the path of the configuration file to read.
 */
roughtime_result_t read_config_file(const char *filename);

/**
 * Reads a configuration value from the global configuration state.
 * @param key the key to get the configured value for.
 * @param value return pointer for the requested configuration value.
 * @return ROUGHTIME_SUCCESS if the key is found in the global configuration state and
 * ROUGHTIME_NOT_FOUND otherwise.
 */
roughtime_result_t get_config(const char *restrict key, const char **restrict value);

/** Securely clears the global configuration state. */
void clear_config(void);

#endif /* __CONFIG_H__ */

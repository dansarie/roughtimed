/* config.h

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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "roughtimed.h"

roughtime_result_t read_config_file(const char *filename);
roughtime_result_t get_config(const char *restrict key, const char **restrict value);
void clear_config();

#endif /* __CONFIG_H__ */

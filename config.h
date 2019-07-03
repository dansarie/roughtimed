/* config.h
   Copyright (C) 2019 Marcus Dansarie <marcus@dansarie.se> */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "roughtimed.h"

roughtime_result_t read_config_file();
roughtime_result_t get_config(const char *restrict key, const char **restrict value);
void clear_config();

#endif /* __CONFIG_H__ */

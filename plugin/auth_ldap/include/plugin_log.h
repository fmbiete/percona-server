#ifndef _PLUGIN_LOG_ALP_H_
/* Copyright (c) 2019 Francisco Miguel Biete Banon. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */
#define _PLUGIN_LOG_ALP_H_

#include <string>

#define ALP_LOG_NONE 1
#define ALP_LOG_ERR 2
#define ALP_LOG_WARN 3
#define ALP_LOG_INFO 4
#define ALP_LOG_DBUG 5

#ifndef MYSQL_ABI_CHECK
#include <stdarg.h>
#endif

#include "mysql/plugin_auth.h"

// Plugin logging
void set_alp_log_plugin(MYSQL_PLUGIN *plugin);
void set_alp_log_status(unsigned int log_status);
void alp_log(const unsigned int level, const char *format, ...)
    MY_ATTRIBUTE((format(printf, 2, 3)));

#define log_debug(fmt, ...) alp_log(ALP_LOG_DBUG, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) alp_log(ALP_LOG_ERR, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) alp_log(ALP_LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) alp_log(ALP_LOG_WARN, fmt, ##__VA_ARGS__)

#endif  // _PLUGIN_LOG_ALP_H_

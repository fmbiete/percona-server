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

#include "plugin/auth_ldap/include/plugin_log.h"

#include "mysql/service_my_plugin_log.h"

#include <iostream>

#define LOG_BUFF_MAX 8192

static unsigned int alp_log_status;
static MYSQL_PLUGIN *alp_plugin;

void alp_log(const unsigned int level, const char *fmt, ...) {
  if (level <= alp_log_status) {
    enum plugin_log_level my_level = MY_INFORMATION_LEVEL;
    switch (level) {
      case ALP_LOG_ERR:
        my_level = MY_ERROR_LEVEL;
        break;
      case ALP_LOG_WARN:
        my_level = MY_WARNING_LEVEL;
        break;
    }
    // alp_plugin.name.str
    char msg[LOG_BUFF_MAX];
    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg) - 1, fmt, args);
    va_end(args);

    // FIXME: warning: format not a string literal and no format arguments [-Wformat-security]
    my_plugin_log_message(alp_plugin, my_level, msg);
  }
}

void set_alp_log_plugin(MYSQL_PLUGIN *plugin) { alp_plugin = plugin; }

void set_alp_log_status(unsigned int log_status) {
  //std::cerr << "alp_log_status " << alp_log_status << " " << log_status << '\n';
  alp_log_status = log_status;
}

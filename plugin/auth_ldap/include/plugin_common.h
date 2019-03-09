#ifndef _PLUGIN_COMMON_ALP_H
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
#define _PLUGIN_COMMON_ALP_H

#include "m_string.h"
#include "my_dbug.h"
#include "my_sys.h"
#include "mysql/plugin_auth.h"

int auth_ldap_authenticate_user(alp::AuthLDAPBase *obj, MYSQL_PLUGIN_VIO *vio,
                                MYSQL_SERVER_AUTH_INFO *info);

#endif  // _PLUGIN_COMMON_ALP_H

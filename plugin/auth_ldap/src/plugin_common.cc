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

#include "plugin/auth_ldap/include/auth_ldap_base.h"
#include "plugin/auth_ldap/include/plugin_common.h"

// Plugin logging
#include "mysql/components/my_service.h"
#include "mysql/components/service_implementation.h"
#include "mysql/components/services/log_builtins.h"

static SERVICE_TYPE(registry) *reg_srv = nullptr;
SERVICE_TYPE(log_builtins) *log_bi = nullptr;
SERVICE_TYPE(log_builtins_string) *log_bs = nullptr;

int auth_ldap_common_init() {
  if (init_logging_service_for_plugin(&reg_srv, &log_bi, &log_bs)) return 1;

  return 0;
}

int auth_ldap_common_deinit() {
  deinit_logging_service_for_plugin(&reg_srv, &log_bi, &log_bs);

  return 0;
}

int auth_ldap_common_authenticate_user(alp::AuthLDAPBase *obj,
                                       MYSQL_PLUGIN_VIO *vio,
                                       MYSQL_SERVER_AUTH_INFO *info) {
  DBUG_ENTER("auth_ldap_common_authenticate_user");

  /* send a password question */
  if (vio->write_packet(vio, (const unsigned char *)PASSWORD_QUESTION, 1)) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to write password packet", info->user_name);
    DBUG_RETURN(CR_ERROR);
  }

  unsigned char *password;
  if ((vio->read_packet(vio, &password)) < 0) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to read password packet");
    DBUG_RETURN(CR_ERROR);
  }
  info->password_used = PASSWORD_USED_YES;

  if (obj->prepare(info->user_name, info->auth_string,
                   info->auth_string_length)) {
    bool res = obj->bind(static_cast<char *>(static_cast<void *>(password)));
    if (res) {
      DBUG_RETURN(CR_OK);
    } else {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "LDAP bind unsuccessful");
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, obj->error());
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, info->user_name);
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, obj->debug_uri());
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, obj->debug_dn());
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, obj->debug_default_dn());
      DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);
    }
  } else {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "Failed to prepare auth ldap");
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, obj->error());
    DBUG_RETURN(CR_AUTH_PLUGIN_ERROR);
  }

  MY_ASSERT_UNREACHABLE();
  DBUG_RETURN(CR_ERROR);
  // TODO: proxy support // char authenticated_as[MYSQL_USERNAME_LENGTH+1];
}

int auth_ldap_common_generate_auth_string_hash(char *outbuf,
                                               unsigned int *buflen,
                                               const char *inbuf,
                                               unsigned int inbuflen) {
  /*
    fail if buffer specified by server cannot be copied to output buffer
  */
  if (*buflen < inbuflen) return 1; /* error */
  strncpy(outbuf, inbuf, inbuflen);
  *buflen = strlen(inbuf);
  return 0; /* success */
}

int auth_ldap_common_validate_auth_string_hash(char *const buf
                                               __attribute__((unused)),
                                               unsigned int len
                                               __attribute__((unused))) {
  return 0; /* success */
}

int auth_ldap_common_set_salt(const char *password __attribute__((unused)),
                              unsigned int password_len __attribute__((unused)),
                              unsigned char *salt __attribute__((unused)),
                              unsigned char *salt_len) {
  *salt_len = 0;
  return 0; /* success */
}

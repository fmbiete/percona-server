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

#include "mysql/components/services/log_builtins.h"

int auth_ldap_authenticate_user(alp::AuthLDAPBase *obj, MYSQL_PLUGIN_VIO *vio,
                                MYSQL_SERVER_AUTH_INFO *info) {
  DBUG_ENTER("auth_ldap_authenticate_user");

  unsigned char *password;
  if ((vio->read_packet(vio, &password)) < 0) {
    // LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
    //              "Failed to read password packet");
    DBUG_RETURN(CR_ERROR);
  }
  info->password_used = PASSWORD_USED_YES;

  if (obj->prepare(info->user_name, info->auth_string,
                   info->auth_string_length)) {
    bool res = obj->bind(static_cast<char *>(static_cast<void *>(password)));
    delete password;
    if (res) {
      DBUG_RETURN(CR_OK);
    } else {
      DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);
    }
  } else {
    delete password;
    DBUG_RETURN(CR_AUTH_PLUGIN_ERROR);
  }

  // Unreachable code: something went very bad
  DBUG_RETURN(CR_ERROR);
  // TODO: proxy support // char authenticated_as[MYSQL_USERNAME_LENGTH+1];
}

int auth_ldap_generate_auth_string_hash(char *outbuf, unsigned int *buflen,
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

int auth_ldap_validate_auth_string_hash(char *const buf __attribute__((unused)),
                                        unsigned int len
                                        __attribute__((unused))) {
  return 0; /* success */
}

int auth_ldap_set_salt(const char *password __attribute__((unused)),
                       unsigned int password_len __attribute__((unused)),
                       unsigned char *salt __attribute__((unused)),
                       unsigned char *salt_len) {
  *salt_len = 0;
  return 0; /* success */
}

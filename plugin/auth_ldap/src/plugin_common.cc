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

#include "plugin/auth_ldap/include/plugin_common.h"

#include "plugin/auth_ldap/include/plugin_log.h"

// static SERVICE_TYPE(registry) *reg_srv = nullptr;
// SERVICE_TYPE(log_builtins) *log_bi = nullptr;
// SERVICE_TYPE(log_builtins_string) *log_bs = nullptr;

int auth_ldap_common_init() {
  // if (init_logging_service_for_plugin(&reg_srv, &log_bi, &log_bs)) return 1;

  return 0;
}

int auth_ldap_common_deinit(alp::AuthLDAPConnectionPool *connPool) {
  log_debug("Destroying LDAP connection pool");
  delete connPool;

  // deinit_logging_service_for_plugin(&reg_srv, &log_bi, &log_bs);

  return 0;
}

int auth_ldap_common_authenticate_user(alp::AuthLDAPConnectionPool *connPool,
                                       MYSQL_PLUGIN_VIO *vio,
                                       MYSQL_SERVER_AUTH_INFO *info,
                                       const char *server_host,
                                       unsigned int server_port, bool ssl,
                                       bool tls, const char *ca_path,
                                       const char *user_search_attr) {
  DBUG_ENTER("auth_ldap_common_authenticate_user");

  // If the account explicitily name a user DN don't use this var
  // If the account doesn't explicitily name a user DN use this var to perform
  // the initial bind and search for the user DN
  /* send a password question */
  if (vio->write_packet(vio, (const unsigned char *)PASSWORD_QUESTION, 1)) {
    log_error("Failed to write password packet");
    DBUG_RETURN(CR_ERROR);
  }

  unsigned char *upassword;
  if ((vio->read_packet(vio, &upassword)) < 0) {
    log_error("Failed to read password packet");
    DBUG_RETURN(CR_ERROR);
  }
  info->password_used = PASSWORD_USED_YES;
  char *password = static_cast<char *>(static_cast<void *>(upassword));
  // We don't need to free password memory

  if (info->auth_string_length > 0) {
    log_debug("Authenticating with auth_string %s", info->auth_string);
    alp::AuthLDAPConnection *conn = new alp::AuthLDAPConnection(
        STR_NULL(server_host), server_port, ssl, tls, STR_NULL(ca_path),
        STR_NULL(info->auth_string), STR_NULL(user_search_attr),
        STR_NULL(info->user_name), STR_NULL(password));
    int res = conn->get_error();
    delete conn;
    DBUG_RETURN(res);
  } else {
    //log_debug("Authenticating with bind_root_dn %s", bind_root_dn);
    alp::AuthLDAPConnection *conn = connPool->borrow();
    if (conn == nullptr) {
      // TODO: print error
      DBUG_RETURN(CR_AUTH_PLUGIN_ERROR);
    } else {
      // TODO: search user
      // TODO: bind as user
      // TODO: get groups
      conn->unborrow();
      conn = nullptr;
    }
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

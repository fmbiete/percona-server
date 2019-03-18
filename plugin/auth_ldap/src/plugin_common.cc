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

#include <list>
#include <string>

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

int auth_ldap_common_authenticate_user(
    alp::AuthLDAPConnectionPool *connPool, MYSQL_PLUGIN_VIO *vio,
    MYSQL_SERVER_AUTH_INFO *info, const char *server_host,
    unsigned int server_port, bool ssl, bool tls, const char *ca_path,
    const char *user_search_attr, const char *group_search_attr,
    const char *group_search_filter, const char *base_dn) {
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

  log_error("Username: %s Authenticated_as: %s", info->user_name,
            info->authenticated_as);

  if (info->auth_string_length > 0) {
    // TODO: CREATE USER ''@'%'  IDENTIFIED WITH authentication_ldap_sasl  BY '+ou=People,dc=example,dc=com#grp1=usera,grp2,grp3=userc';
    log_debug("Authenticating with auth_string %s", info->auth_string);
    alp::AuthLDAPConnection *conn = new alp::AuthLDAPConnection(
        STR_NULL(server_host), server_port, ssl, tls, STR_NULL(ca_path),
        STR_NULL(info->auth_string), STR_NULL(user_search_attr),
        STR_NULL(info->user_name), STR_NULL(password));
    int res = conn->get_error();
    delete conn;
    DBUG_RETURN(res);
  } else {
    // log_debug("Authenticating with bind_root_dn %s", bind_root_dn);
    alp::AuthLDAPConnection *conn = connPool->borrow();
    if (conn == nullptr) {
      log_error("Couldn't get an available LDAP connection from the pool");
      // TODO: print pool debug info
      DBUG_RETURN(CR_AUTH_PLUGIN_ERROR);
    } else {
      std::string bind_user =
          conn->search_dn(STR_NULL(info->user_name), STR_NULL(user_search_attr),
                          STR_NULL(base_dn));
      if (bind_user.empty()) {
        log_warn("Coulnd't find the specified user %s", info->user_name);
        conn->unborrow();
        DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);
      } else {
        log_debug("User DN found %s", bind_user.c_str());
        if (conn->bind(bind_user, STR_NULL(password)) == CR_OK) {
          log_debug("User validated");
          if (strlen(info->authenticated_as) == 0) {
            log_debug("Authenticating with proxy user");
            std::list<std::string> groups = conn->search_group(
                info->user_name, bind_user, STR_NULL(group_search_attr),
                STR_NULL(group_search_filter), STR_NULL(base_dn));
            // If we are here, is because we haven't specified a group priority
            // Login will success only if the list returns 1 group only
            if(groups.size() == 1) {
              // TODO: what happens if the group doesn't map to a mysql user??
              log_debug("User maps to 1 group %s", groups.front().c_str());
              strcpy(info->authenticated_as, groups.front().c_str());
              conn->unborrow();
              DBUG_RETURN(CR_OK);
            } else {
              log_debug("User maps to 0 or more than 1 group");
              conn->unborrow();
              DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);
            }
          } else {
            conn->unborrow();
            DBUG_RETURN(CR_OK);
          }
        } else {
          log_warn("Couldn't login as specified user %s", info->user_name);
          conn->unborrow();
          DBUG_RETURN(CR_AUTH_USER_CREDENTIALS);
        }
      }
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

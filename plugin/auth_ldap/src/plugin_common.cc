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

#include <algorithm>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <list>
#include <string>

// Private declarations
char *ask_password_simple(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info);
alp::AuthLDAPConnection *get_ldap_connection(alp::AuthLDAPConnectionPool *pool);
int proxy_authentication(alp::AuthLDAPConnection *conn,
                         alp::AuthLDAPConnection *uconn, char *authenticated_as,
                         std::string user_name, std::string password,
                         std::string auth_string, std::string user_search_attr,
                         std::string group_search_attr,
                         std::string group_search_filter,
                         std::string bind_base_dn);
int proxy_authentication_with_auth_string(
    alp::AuthLDAPConnection *conn, std::string user_name,
    std::string auth_string, std::string user_search_attr,
    std::string group_search_attr, std::string group_search_filter,
    std::string bind_base_dn, std::string *user_dn, std::string *user_group);
int proxy_authentication_without_auth_string(
    alp::AuthLDAPConnection *conn, std::string user_name,
    std::string user_search_attr, std::string group_search_attr,
    std::string group_search_filter, std::string bind_base_dn,
    std::string *user_dn, std::string *user_group);
int user_authentication(alp::AuthLDAPConnection *conn,
                        alp::AuthLDAPConnection *uconn, std::string user_name,
                        std::string password, std::string auth_string,
                        std::string user_search_attr, std::string bind_base_dn);
int user_authentication_with_auth_string(std::string user_name,
                                         std::string auth_string,
                                         std::string user_search_attr,
                                         std::string *user_dn);
int user_authentication_without_auth_string(alp::AuthLDAPConnection *conn,
                                            std::string user_name,
                                            std::string user_search_attr,
                                            std::string bind_base_dn,
                                            std::string *user_dn);
int user_bind(alp::AuthLDAPConnection *uconn, std::string user_dn,
              std::string password, std::string proxy);
int user_search(alp::AuthLDAPConnection *conn, std::string user_name,
                std::string user_search_attr, std::string bind_base_dn,
                std::string *user_dn);

int auth_ldap_common_init() { return 0; }

int auth_ldap_common_deinit(alp::AuthLDAPConnectionPool *connPool) {
  log_debug("Destroying LDAP connection pool");
  delete connPool;

  return 0;
}

int auth_ldap_common_authenticate_user(MYSQL_PLUGIN_VIO *vio,
                                       MYSQL_SERVER_AUTH_INFO *info,
                                       alp::AuthLDAPConnectionPool *pool,
                                       const char *user_search_attr,
                                       const char *group_search_attr,
                                       const char *group_search_filter,
                                       const char *bind_base_dn) {
  log_debug("auth_ldap_common_authenticate_user()");
  int res = CR_ERROR;

  char *password = ask_password_simple(vio, info);
  if (password == nullptr) {
    return CR_AUTH_PLUGIN_ERROR;
  }

  alp::AuthLDAPConnection *conn = get_ldap_connection(pool);
  if (conn == nullptr) {
    return CR_AUTH_PLUGIN_ERROR;
  }

  alp::AuthLDAPConnection *uconn = pool->newConnection(false);

  unsigned int len_authenticated_as = strlen(info->authenticated_as);
  if (len_authenticated_as == 0) {
    res = proxy_authentication(
        conn, uconn, info->authenticated_as, STR_NULL(info->user_name),
        STR_NULL(password), STR_NULL(info->auth_string),
        STR_NULL(user_search_attr), STR_NULL(group_search_attr),
        STR_NULL(group_search_filter), STR_NULL(bind_base_dn));
  } else {
    res =
        user_authentication(conn, uconn, STR_NULL(info->user_name),
                            STR_NULL(password), STR_NULL(info->auth_string),
                            STR_NULL(user_search_attr), STR_NULL(bind_base_dn));
  }

  conn->unborrow();
  delete uconn;

  log_debug("auth_ldap_common_authenticate_user() = %d", res);
  return res;
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

/******************************************************************************
 * PRIVATE FUNCTIONS
 ******************************************************************************/

char *ask_password_simple(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info) {
  char *password = nullptr;

  // send a password question
  if (vio->write_packet(vio, (const unsigned char *)PASSWORD_QUESTION, 1)) {
    log_error("Failed to write password packet");
  } else {
    // read the password answer
    unsigned char *upassword;
    if ((vio->read_packet(vio, &upassword)) < 0) {
      log_error("Failed to read password packet");
    } else {
      info->password_used = PASSWORD_USED_YES;
      password = static_cast<char *>(static_cast<void *>(upassword));
      // We don't need to free 'password' memory (causes a sigfault)
    }
  }

  return password;
}

alp::AuthLDAPConnection *get_ldap_connection(
    alp::AuthLDAPConnectionPool *pool) {
  alp::AuthLDAPConnection *conn = nullptr;

  // Are we using connection pool?
  if (pool->max_size() == 0) {
    // No: create new connection in this thread
    conn = pool->newConnection(true);
  } else {
    // Yes: get a connection from the pool
    conn = pool->getConnection();
    if (conn == nullptr) {
      log_error("There are no connections available in the LDAP pool");
      pool->debug_info();
    }
  }

  return conn;
}

int user_bind(alp::AuthLDAPConnection *uconn, std::string user_dn,
              std::string password, std::string proxy) {
  int res = CR_AUTH_USER_CREDENTIALS;
  if (uconn->bind(user_dn, password)) {
    log_debug("User authentication success: [%s] proxy as [%s]",
              user_dn.c_str(), proxy.c_str());
    res = CR_OK;
  } else {
    log_debug("User authentication failed: [%s] proxy as [%s]", user_dn.c_str(),
              proxy.c_str());
  }

  return res;
}

int user_search(alp::AuthLDAPConnection *conn, std::string user_name,
                std::string user_search_attr, std::string bind_base_dn,
                std::string *user_dn) {
  *user_dn = conn->search_dn(user_name, user_search_attr, bind_base_dn);
  if (user_dn->empty()) {
    log_warn("User not found");
    log_debug("user_name: [%s] user_search_attr: [%s] bind_base_dn: [%s]",
              user_name.c_str(), user_search_attr.c_str(),
              bind_base_dn.c_str());
    return CR_AUTH_USER_CREDENTIALS;
  }

  return CR_OK;
}

int proxy_authentication_without_auth_string(
    alp::AuthLDAPConnection *conn, std::string user_name,
    std::string user_search_attr, std::string group_search_attr,
    std::string group_search_filter, std::string bind_base_dn,
    std::string *user_dn, std::string *user_group) {
  int res =
      user_search(conn, user_name, user_search_attr, bind_base_dn, user_dn);
  if (res != CR_OK) {
    return res;
  }

  std::list<std::string> user_groups =
      conn->search_groups(user_name, *user_dn, group_search_attr,
                          group_search_filter, bind_base_dn);
  if (user_groups.size() == 1) {
    *user_group = user_groups.front();
    log_debug("User with 1 group %s", user_group->c_str());
  } else {
    log_warn(
        "User must be mapped to exactly 1 group if group mappings in "
        "auth_string are not used");
    log_debug("groups found: %lu", user_groups.size());
    return CR_AUTH_USER_CREDENTIALS;
  }

  return CR_OK;
}

int proxy_authentication_with_auth_string(
    alp::AuthLDAPConnection *conn, std::string user_name,
    std::string auth_string, std::string user_search_attr,
    std::string group_search_attr, std::string group_search_filter,
    std::string bind_base_dn, std::string *user_dn, std::string *user_group) {
  std::string auth_str = boost::algorithm::trim_copy(auth_string);
  std::string base_search = bind_base_dn;
  std::vector<std::string> parts;
  boost::algorithm::split(parts, auth_str, boost::is_any_of("#"));

  // User search
  if (parts.size() >= 1) {
    if (parts[0][0] == '+') {
      *user_dn = user_search_attr + "=" + user_name + "," + parts[0].substr(1);
      log_debug("Using auth_string as user_dn: %s", user_dn->c_str());
    } else {
      boost::algorithm::trim(parts[0]);
      if (!parts[0].empty()) {
        log_debug("Using auth_string as base_search: %s", base_search.c_str());
        base_search = parts[0];
      }
      int res =
          user_search(conn, user_name, user_search_attr, base_search, user_dn);
      if (res != CR_OK) {
        return res;
      }
    }
  }

  // Group search
  std::vector<std::string> group_maps;
  if (parts.size() == 2) {
    std::list<std::string> user_groups =
        conn->search_groups(user_name, *user_dn, group_search_attr,
                            group_search_filter, base_search);
    boost::algorithm::split(group_maps, parts[1], boost::is_any_of(","));
    for (std::string const &s : group_maps) {
      std::vector<std::string> map;
      boost::algorithm::split(map, s, boost::is_any_of("="));
      // look for the group name (map[0]) in user_groups
      if (std::binary_search(user_groups.begin(), user_groups.end(), map[0])) {
        if (map.size() == 2) {
          *user_group = map[1];
        } else {
          *user_group = map[0];
        }
        return CR_OK;
      }
    }
  }

  // we didn't found a mapping group
  return CR_AUTH_USER_CREDENTIALS;
}

int proxy_authentication(alp::AuthLDAPConnection *conn,
                         alp::AuthLDAPConnection *uconn, char *authenticated_as,
                         std::string user_name, std::string password,
                         std::string auth_string, std::string user_search_attr,
                         std::string group_search_attr,
                         std::string group_search_filter,
                         std::string bind_base_dn) {
  int res = CR_AUTH_PLUGIN_ERROR;
  std::string user_dn, user_group;

  if (auth_string.empty()) {
    res = proxy_authentication_without_auth_string(
        conn, user_name, user_search_attr, group_search_attr,
        group_search_filter, bind_base_dn, &user_dn, &user_group);
  } else {
    res = proxy_authentication_with_auth_string(
        conn, user_name, auth_string, user_search_attr, group_search_attr,
        group_search_filter, bind_base_dn, &user_dn, &user_group);
  }

  if (res == CR_OK) {
    res = user_bind(uconn, user_dn, password, user_group);
    if (res == CR_OK) strcpy(authenticated_as, user_group.c_str());
  }

  return res;
}

int user_authentication_without_auth_string(alp::AuthLDAPConnection *conn,
                                            std::string user_name,
                                            std::string user_search_attr,
                                            std::string bind_base_dn,
                                            std::string *user_dn) {
  int res =
      user_search(conn, user_name, user_search_attr, bind_base_dn, user_dn);
  return res;
}

int user_authentication_with_auth_string(std::string user_name,
                                         std::string auth_string,
                                         std::string user_search_attr,
                                         std::string *user_dn) {
  if (auth_string[0] == '+') {
    *user_dn = user_search_attr + "=" + user_name + "," + auth_string.substr(1);
  } else {
    *user_dn = auth_string;
  }

  return CR_OK;
}

int user_authentication(alp::AuthLDAPConnection *conn,
                        alp::AuthLDAPConnection *uconn, std::string user_name,
                        std::string password, std::string auth_string,
                        std::string user_search_attr,
                        std::string bind_base_dn) {
  int res = CR_AUTH_PLUGIN_ERROR;
  std::string user_dn;
  if (auth_string.empty()) {
    res = user_authentication_without_auth_string(
        conn, user_name, user_search_attr, bind_base_dn, &user_dn);
  } else {
    res = user_authentication_with_auth_string(user_name, auth_string,
                                               user_search_attr, &user_dn);
  }

  if (res == CR_OK) {
    res = user_bind(uconn, user_dn, password, "");
  }

  return res;
}

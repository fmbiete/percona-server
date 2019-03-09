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
alp::AuthLDAPConnection *get_ldap_connection(alp::AuthLDAPConnectionPool *pool);
int proxy_authentication(alp::AuthLDAPConnection *conn_pooled,
                         alp::AuthLDAPConnection *conn_no_pooled,
                         char *authenticated_as, std::string user_name,
                         std::string password, std::string auth_string,
                         std::string user_search_attr,
                         std::string group_search_attr,
                         std::string group_search_filter,
                         std::string bind_base_dn);
int proxy_authentication_with_auth_string(
    alp::AuthLDAPConnection *conn_pooled, std::string user_name,
    std::string user_search_attr, std::string group_search_attr,
    std::string group_search_filter, std::string bind_base_dn,
    std::string user_dn, std::string *user_group);
int proxy_authentication_without_auth_string(
    alp::AuthLDAPConnection *conn_pooled, std::string user_name,
    std::string group_search_attr, std::string group_search_filter,
    std::string bind_base_dn, std::string user_dn, std::string *user_group);
int user_authentication(alp::AuthLDAPConnection *conn_pooled,
                        alp::AuthLDAPConnection *conn_no_pooled,
                        std::string user_name, std::string password,
                        std::string auth_string, std::string user_search_attr,
                        std::string bind_base_dn, std::string *user_dn);
int user_authentication_with_auth_string(std::string user_name,
                                         std::string auth_string,
                                         std::string user_search_attr,
                                         std::string *user_dn);
int user_authentication_without_auth_string(alp::AuthLDAPConnection *conn,
                                            std::string user_name,
                                            std::string user_search_attr,
                                            std::string bind_base_dn,
                                            std::string *user_dn);
int user_bind(alp::AuthLDAPConnection *conn_no_pooled, std::string user_dn,
              std::string password);
int user_search(alp::AuthLDAPConnection *conn_pooled, std::string user_name,
                std::string user_search_attr, std::string bind_base_dn,
                std::string *user_dn);

int auth_ldap_common_init() { return 0; }

int auth_ldap_common_deinit(alp::AuthLDAPConnectionPool *connPool) {
  log_srv_dbg("Destroying LDAP connection pool");
  delete connPool;

  return 0;
}

int auth_ldap_common_authenticate_user(
    MYSQL_PLUGIN_VIO *vio MY_ATTRIBUTE((unused)), MYSQL_SERVER_AUTH_INFO *info,
    const char *password, alp::AuthLDAPConnectionPool *pool,
    const char *user_search_attr, const char *group_search_attr,
    const char *group_search_filter, const char *bind_base_dn) {
  std::stringstream log_stream;

  log_srv_dbg("auth_ldap_common_authenticate_user()");
  int res = CR_ERROR;

  alp::AuthLDAPConnection *conn_pooled = get_ldap_connection(pool);
  if (conn_pooled == nullptr) {
    return CR_AUTH_PLUGIN_ERROR;
  }

  alp::AuthLDAPConnection *conn_no_pooled = pool->new_connection(false);

  unsigned int len_authenticated_as = strlen(info->authenticated_as);
  if (len_authenticated_as == 0) {
    res = proxy_authentication(
        conn_pooled, conn_no_pooled, info->authenticated_as,
        STR_NULL(info->user_name), STR_NULL(password),
        STR_NULL(info->auth_string), STR_NULL(user_search_attr),
        STR_NULL(group_search_attr), STR_NULL(group_search_filter),
        STR_NULL(bind_base_dn));
  } else {
    std::string user_dn;
    res = user_authentication(
        conn_pooled, conn_no_pooled, STR_NULL(info->user_name),
        STR_NULL(password), STR_NULL(info->auth_string),
        STR_NULL(user_search_attr), STR_NULL(bind_base_dn), &user_dn);
  }

  conn_pooled->unborrow();
  delete conn_no_pooled;

  log_stream << "auth_ldap_common_authenticate_user() = " << res;
  log_srv_dbg(log_stream.str());
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

alp::AuthLDAPConnection *get_ldap_connection(
    alp::AuthLDAPConnectionPool *pool) {
  alp::AuthLDAPConnection *conn = nullptr;

  // Are we using connection pool?
  if (pool->max_size() == 0) {
    // No: create new connection in this thread
    conn = pool->new_connection(true);
  } else {
    // Yes: get a connection from the pool
    conn = pool->get_connection();
    if (conn == nullptr) {
      log_srv_error("There are no connections available in the LDAP pool");
      pool->debug_info();
    }
  }

  return conn;
}

int user_bind(alp::AuthLDAPConnection *conn_no_pooled, std::string user_dn,
              std::string password) {
  int res = CR_AUTH_USER_CREDENTIALS;
  std::stringstream log_stream;
  if (conn_no_pooled->bind(user_dn, password)) {
    log_stream << "User authentication success: [" << user_dn << "]";
    res = CR_OK;
  } else {
    log_stream << "User authentication failed: [" << user_dn << "]";
  }
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return res;
}

int user_search(alp::AuthLDAPConnection *conn_pooled, std::string user_name,
                std::string user_search_attr, std::string bind_base_dn,
                std::string *user_dn) {
  log_srv_dbg("user_search()");
  std::stringstream log_stream;
  *user_dn = conn_pooled->search_dn(user_name, user_search_attr, bind_base_dn);
  if (user_dn->empty()) {
    log_srv_warn("User not found");
    log_stream << "user_name: [" << user_name << "] user_search_attr: ["
               << user_search_attr << "] bind_base_dn: [" << bind_base_dn
               << "]";
    log_srv_dbg(log_stream.str());
    return CR_AUTH_USER_CREDENTIALS;
  }

  return CR_OK;
}

int proxy_authentication_without_auth_string(
    alp::AuthLDAPConnection *conn_pooled, std::string user_name,
    std::string group_search_attr, std::string group_search_filter,
    std::string bind_base_dn, std::string user_dn, std::string *user_group) {
  log_srv_dbg("proxy_authentication_without_auth_string()");
  int res = CR_OK;

  std::stringstream log_stream;
  std::list<std::string> user_groups = conn_pooled->search_groups(
      user_name, user_dn, group_search_attr, group_search_filter, bind_base_dn);
  if (user_groups.size() == 1) {
    *user_group = user_groups.front();
    log_stream << "User with 1 group " << *user_group;
  } else {
    res = CR_AUTH_USER_CREDENTIALS;
    log_srv_warn(
        "User must be mapped to exactly 1 group if group mappings in "
        "auth_string are not used");
    log_stream << "groups found: " << user_groups.size();
  }
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return res;
}

int proxy_authentication_with_auth_string(
    alp::AuthLDAPConnection *conn_pooled, std::string user_name,
    std::string auth_string, std::string group_search_attr,
    std::string group_search_filter, std::string bind_base_dn,
    std::string user_dn, std::string *user_group) {
  log_srv_dbg("proxy_authentication_with_auth_string()");
  std::stringstream log_stream;
  std::vector<std::string> parts;
  boost::algorithm::split(parts, auth_string, boost::is_any_of("#"));

  // '#mysql=mysqlgroup2,mysqlgroup1';
  // Group search
  std::vector<std::string> group_maps;
  if (parts.size() == 2) {
    std::list<std::string> user_groups =
        conn_pooled->search_groups(user_name, user_dn, group_search_attr,
                                   group_search_filter, bind_base_dn);
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
        log_stream << "group mapping identified: " << *user_group;
        log_srv_dbg(log_stream.str());
        log_stream.str("");
        return CR_OK;
      }
    }
  }

  log_srv_dbg("We didn't found a mapping group");
  return CR_AUTH_USER_CREDENTIALS;
}

int proxy_authentication(alp::AuthLDAPConnection *conn_pooled,
                         alp::AuthLDAPConnection *conn_no_pooled,
                         char *authenticated_as, std::string user_name,
                         std::string password, std::string auth_string,
                         std::string user_search_attr,
                         std::string group_search_attr,
                         std::string group_search_filter,
                         std::string bind_base_dn) {
  log_srv_dbg("proxy_authentication()");
  int res = CR_AUTH_PLUGIN_ERROR;
  std::string user_dn, user_group;
  std::string auth_str = boost::algorithm::trim_copy(auth_string);

  std::string p_auth_string;
  if (!auth_string.empty()) {
    std::vector<std::string> parts;
    boost::algorithm::split(parts, auth_string, boost::is_any_of("#"));
    p_auth_string = parts[0];
  }

  res = user_authentication(conn_pooled, conn_no_pooled, user_name, password,
                            p_auth_string, user_search_attr, bind_base_dn,
                            &user_dn);
  if (res != CR_OK) {
    return res;
  }

  if (auth_string.empty()) {
    res = proxy_authentication_without_auth_string(
        conn_pooled, user_name, group_search_attr, group_search_filter,
        bind_base_dn, user_dn, &user_group);
  } else {
    res = proxy_authentication_with_auth_string(
        conn_pooled, user_name, auth_string, group_search_attr,
        group_search_filter, bind_base_dn, user_dn, &user_group);
  }

  if (res == CR_OK) {
    strcpy(authenticated_as, user_group.c_str());
  }

  return res;
}

int user_authentication_without_auth_string(
    alp::AuthLDAPConnection *conn_pooled, std::string user_name,
    std::string user_search_attr, std::string bind_base_dn,
    std::string *user_dn) {
  log_srv_dbg("user_authentication_without_auth_string()");
  int res = user_search(conn_pooled, user_name, user_search_attr, bind_base_dn,
                        user_dn);
  return res;
}

int user_authentication_with_auth_string(std::string user_name,
                                         std::string auth_string,
                                         std::string user_search_attr,
                                         std::string *user_dn) {
  log_srv_dbg("user_authentication_with_auth_string()");
  std::stringstream log_stream;
  if (auth_string[0] == '+') {
    *user_dn = user_search_attr + "=" + user_name + "," + auth_string.substr(1);
    log_stream << "Calculated user_dn: ";
  } else {
    *user_dn = auth_string;
    log_stream << "Full user_dn specified: ";
  }
  log_stream << *user_dn;
  log_srv_dbg(log_stream.str());

  return CR_OK;
}

int user_authentication(alp::AuthLDAPConnection *conn_pooled,
                        alp::AuthLDAPConnection *conn_no_pooled,
                        std::string user_name, std::string password,
                        std::string auth_string, std::string user_search_attr,
                        std::string bind_base_dn, std::string *user_dn) {
  log_srv_dbg("user_authentication()");
  int res = CR_AUTH_PLUGIN_ERROR;
  if (auth_string.empty()) {
    res = user_authentication_without_auth_string(
        conn_pooled, user_name, user_search_attr, bind_base_dn, user_dn);
  } else {
    res = user_authentication_with_auth_string(user_name, auth_string,
                                               user_search_attr, user_dn);
  }

  if (res == CR_OK) {
    res = user_bind(conn_no_pooled, *user_dn, password);
  }

  return res;
}

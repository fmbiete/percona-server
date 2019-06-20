#ifndef _AUTH_LDAP_CONNECTION_MPALDAP_H
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
#define _AUTH_LDAP_CONNECTION_MPALDAP_H

#include <ctime>
#include <list>
#include <string>

#include <ldap.h>

namespace mysql {
namespace plugin {
namespace auth_ldap {
class AuthLDAPConnection {
 public:
  AuthLDAPConnection(std::string server_host, unsigned int server_port,
                     bool ssl, bool tls, std::string ca_path, bool initial_bind,
                     std::string bind_dn, std::string bind_pwd);
  ~AuthLDAPConnection();
  bool bind(std::string bind_dn, std::string bind_pwd,
            bool initial_bind = false);
  inline AuthLDAPConnection *borrow() {
    this->borrowed = true;
    this->borrowed_ts = std::time(nullptr);
    return this;
  };
  inline unsigned int borrowed_for_secs() {
    return std::time(nullptr) - this->borrowed_ts;
  };
  bool is_alive();
  inline bool is_borrowed() { return this->borrowed; }
  inline int get_error() { return this->error; }
  std::string search_dn(std::string user_name, std::string user_search_attr,
                        std::string base_dn);
  std::list<std::string> search_groups(std::string user_name,
                                       std::string bind_user,
                                       std::string group_search_attr,
                                       std::string group_search_filter,
                                       std::string base_dn);
  inline void unborrow() { this->borrowed = false; };

 private:
  std::string get_ldap_uri(std::string server_host, unsigned int server_port,
                           bool ssl);
  bool initiate(std::string server_host, unsigned int server_port, bool ssl,
                bool tls, std::string ca_path);

 private:
  bool borrowed;
  std::time_t borrowed_ts;
  std::time_t created_ts;
  int error;
  LDAP *ldap;
};
}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql

#endif  // _AUTH_LDAP_CONNECTION_MPALDAP_H

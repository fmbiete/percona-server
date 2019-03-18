#ifndef _AUTH_LDAP_CONNECTION_ALP_H
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
#define _AUTH_LDAP_CONNECTION_ALP_H

#include <ctime>
#include <string>

#include <ldap.h>

namespace alp {
class AuthLDAPConnection {
 public:
  AuthLDAPConnection(std::string server_host, unsigned int server_port,
                     bool ssl, bool tls, std::string ca_path,
                     std::string bind_user, std::string uid_attr,
                     std::string user_name, std::string bind_pwd);
  AuthLDAPConnection(std::string server_host, unsigned int server_port,
                     bool ssl, bool tls, std::string ca_path,
                     std::string bind_dn, std::string bind_pwd);
  ~AuthLDAPConnection();
  int bind(std::string bind_dn, std::string bind_pwd);
  inline AuthLDAPConnection *borrow() {
    this->borrowed = true;
    this->borrowed_ts = std::time(nullptr);
    return this;
  };
  inline unsigned int borrowed_for_secs() {
    return std::time(nullptr) - this->borrowed_ts;
  };
  inline bool is_borrowed() { return this->borrowed; }
  inline int get_error() { return this->error; }
  std::string search_dn(std::string user_name, std::string user_search_attr,
                        std::string base_dn);
  inline void unborrow() { this->borrowed = false; };

 private:
  std::string getLDAPBind(std::string bind_user, std::string uid_attr,
                          std::string user_name);
  std::string getLDAPUri(std::string server_host, unsigned int server_port,
                         bool ssl);
  int initiate(std::string server_host, unsigned int server_port, bool ssl,
               bool tls, std::string ca_path);

 private:
  bool borrowed;
  std::time_t borrowed_ts;
  std::time_t created_ts;
  int error;
  LDAP *ldap;
};
}  // namespace alp

#endif  // _AUTH_LDAP_CONNECTION_ALP_H

#ifndef _AUTH_LDAP_CONNECTION_POOL_ALP_H
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
#define _AUTH_LDAP_CONNECTION_POOL_ALP_H

#include "plugin/auth_ldap/include/auth_ldap_connection.h"

#include <list>
#include <string>

namespace alp {
class AuthLDAPConnectionPool {
 public:
  AuthLDAPConnectionPool(unsigned int initsize, unsigned int maxsize,
                         std::string server_host, unsigned int server_port,
                         bool ssl, bool tls, std::string bind_dn,
                         std::string bind_pwd, std::string ca_path);
  ~AuthLDAPConnectionPool();
  void debug_info();
  AuthLDAPConnection *getConnection();
  AuthLDAPConnection *newConnection(bool initial_bind);
  inline int max_size() { return this->maxsize; }
  void reconfigure(unsigned int initsize, unsigned int maxsize,
                   std::string server_host, unsigned int server_port, bool ss,
                   bool tls, std::string bind_dn, std::string bind_pwd,
                   std::string ca_path);

 private:
  void adjust_size(unsigned int maxsize);
  AuthLDAPConnection *create_connection(bool borrow);
  void destroy(AuthLDAPConnection *con);
  void destroy_all();
  bool destroy_if_expired(AuthLDAPConnection *con);

 private:
  const unsigned int lost_connection_secs = 5;

  std::string bind_dn;
  std::string bind_pwd;
  std::string ca_path;
  unsigned int initsize;
  std::list<AuthLDAPConnection *> list;
  unsigned int maxsize;
  std::string server_host;
  unsigned int server_port;
  bool ssl;
  bool tls;
};
}  // namespace alp

#endif  // _AUTH_LDAP_CONNECTION_POOL_ALP_H

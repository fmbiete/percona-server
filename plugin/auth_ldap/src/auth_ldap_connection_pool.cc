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
#include "plugin/auth_ldap/include/auth_ldap_connection_pool.h"
#include "plugin/auth_ldap/include/plugin_log.h"

namespace alp {
AuthLDAPConnectionPool::AuthLDAPConnectionPool(
    unsigned int initsize, unsigned int maxsize, std::string server_host,
    unsigned int server_port, bool ssl, bool tls, std::string bind_dn,
    std::string bind_pwd, std::string ca_path) {
  this->initsize = 0;
  this->maxsize = 0;
  this->server_port = 0;

  reconfigure(initsize, maxsize, server_host, server_port, ssl, tls, bind_dn,
              bind_pwd, ca_path);
}

AuthLDAPConnectionPool::~AuthLDAPConnectionPool() { destroy_all(); }

void AuthLDAPConnectionPool::reconfigure(
    unsigned int initsize, unsigned int maxsize, std::string server_host,
    unsigned int server_port, bool ssl, bool tls, std::string bind_dn,
    std::string bind_pwd, std::string ca_path) {
  if (this->server_port != server_port || this->ca_path != ca_path ||
      this->server_host != server_host || this->ssl != ssl ||
      this->tls != tls || this->bind_dn != bind_dn ||
      this->bind_pwd != bind_pwd) {
    // Destroy all the connections
    destroy_all();

    this->server_port = server_port;
    this->server_host = server_host;
    this->ssl = ssl;
    this->tls = tls;
    this->bind_dn = bind_dn;
    this->bind_pwd = bind_pwd;
    this->ca_path = ca_path;
    
    // Create a new pool of connections
    for (unsigned int i = 0; i < initsize; i++) {
      create_connection(false);
    }
  } else {
    if (this->list.size() < initsize) {
      // Create elements and add to the list
      for (unsigned int i = this->list.size(); i < initsize; i++) {
        create_connection(false);
      }
    }

    adjust_size(maxsize);
  }
  this->initsize = initsize;
  this->maxsize = maxsize;
}

AuthLDAPConnection *AuthLDAPConnectionPool::borrow() {
  AuthLDAPConnection *obj = nullptr;
  for (AuthLDAPConnection *con : this->list) {
    if (obj == nullptr) {
      if (con->is_borrowed()) {
        if (destroy_if_expired(con)) {
          obj = create_connection(true);
        }
      } else {
        con->borrow();
        obj = con;
      }
    }
  }

  if (obj == nullptr) {
    // We don't have a free connection in the pool
    if (this->maxsize > this->list.size()) {
      // We can add another connection
      obj = create_connection(true);
    }
  }

  adjust_size(this->maxsize);

  return obj;
}

void AuthLDAPConnectionPool::adjust_size(unsigned int maxsize) {
  if (this->list.size() > maxsize) {
    int to_remove = this->list.size() - maxsize;
    int removed = 0;
    for (AuthLDAPConnection *con : list) {
      if (removed < to_remove) {
        if (con->is_borrowed()) {
          if (destroy_if_expired(con)) removed++;
        } else {
          destroy(con);
          removed++;
        }
      }
    }
  }
}

AuthLDAPConnection *AuthLDAPConnectionPool::create_connection(bool borrow) {
  AuthLDAPConnection *obj = new AuthLDAPConnection(server_host, server_port,
                                                   ssl, tls, ca_path, bind_dn, bind_pwd);
  if (borrow) obj->borrow();
  this->list.push_back(obj);
  return obj;
}

void AuthLDAPConnectionPool::destroy_all() {
  // Destroy all connections
  for (AuthLDAPConnection *con : this->list) {
    delete con;
  }
  this->list.clear();
}

void AuthLDAPConnectionPool::destroy(AuthLDAPConnection *con) {
  this->list.remove(con);
  delete con;
}

bool AuthLDAPConnectionPool::destroy_if_expired(AuthLDAPConnection *con) {
  if (con->borrowed_for_secs() > this->lost_connection_secs) {
    destroy(con);
    return true;
  }
  return false;
}
}  // namespace alp

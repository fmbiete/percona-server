#ifndef _AUTH_LDAP_BASE_ALP_H
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
#define _AUTH_LDAP_BASE_ALP_H

#include <string>

#include <ldap.h>

namespace alp {
class AuthLDAPBase {
 public:
  AuthLDAPBase(const char *host, unsigned int port, const char *dn,
               bool simple);
  ~AuthLDAPBase();
  virtual bool bind(char *password) = 0;
  inline const char *debug_default_dn() { return default_dn.c_str(); }
  inline const char *debug_dn() { return dn.c_str(); }
  inline const char *debug_uri() { return uri.c_str(); }
  inline const char *error() { return error_msg.c_str(); }
  inline bool is_error() { return error_msg.empty(); }
  bool prepare(const char *user_name, const char *dn_str,
    unsigned long dn_str_len);

 private:
  void build_dn(const char *user_name, const char *dn_str,
                unsigned long dn_str_len);

 protected:
  inline void get_error(int err) { error_msg = ldap_err2string(err); }

  LDAP *ldap;
  std::string default_dn;
  std::string dn;
  std::string error_msg;
  std::string uri;
};
}  // namespace alp

#endif  // _AUTH_LDAP_BASE_ALP_H

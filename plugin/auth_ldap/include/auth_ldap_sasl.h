#ifndef _AUTH_LDAP_SASL_ALP_H
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
#define _AUTH_LDAP_SASL_ALP_H

#include "plugin/auth_ldap/include/auth_ldap_base.h"

namespace alp {
class AuthLDAPSASL : public AuthLDAPBase {
 public:
  AuthLDAPSASL(const char *host, unsigned int port, const char *dn)
      : AuthLDAPBase(host, port, dn, false){};
  virtual bool bind(char *password);
};
}  // namespace alp
#endif  // _AUTH_LDAP_SASL_ALP_H

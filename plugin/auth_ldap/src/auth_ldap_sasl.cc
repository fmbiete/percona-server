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
#include "plugin/auth_ldap/include/auth_ldap_sasl.h"

#include <ldap.h>

namespace alp {
bool AuthLDAPSASL::bind(const char *password) {
  struct berval *serverCreds;
  struct berval *userCreds = ber_str2bv(strdup(password), 0, 0, nullptr);

  int err = ldap_sasl_bind_s(ldap, dn.c_str(), LDAP_SASL_SIMPLE, userCreds,
                             nullptr, nullptr, &serverCreds);

  set_error(err);
  return err == LDAP_SUCCESS;
}
}  // namespace alp

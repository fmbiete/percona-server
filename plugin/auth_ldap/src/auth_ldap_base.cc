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
#include "plugin/auth_ldap/include/auth_ldap_base.h"

namespace alp {
AuthLDAPBase::AuthLDAPBase(const char *host, unsigned int port, const char *dn,
                           bool simple) {
  this->ldap = nullptr;
  this->sasl = !simple;
  this->uri = std::string(simple ? "ldap://" : "ldaps://")
                  .append(host)
                  .append(":")
                  .append(std::to_string(port));
  this->default_dn = dn;
}

AuthLDAPBase::~AuthLDAPBase() {
  if (ldap) ldap_unbind_ext(ldap, nullptr, nullptr);
}

void AuthLDAPBase::build_dn(const char *user_name, const char *dn_str,
                            unsigned long dn_str_len) {
  dn = std::string("uid=").append(user_name).append(",");
  if (dn_str_len == 0) {
    dn.append(this->default_dn);
  } else {
    // '+ou=People,dc=example,dc=com';
    if (dn_str[0] == '+') {
      dn.append(dn_str);
    } else {
      dn = dn_str;
    }
  }
}

bool AuthLDAPBase::prepare(const char *user_name, const char *dn_str,
                           unsigned long dn_str_len) {
  // TLS configuration must be changed BEFORE initializing ldap or the TLS
  // session you get will have the default configuration Ref:
  // https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=823232
  int reqCert = LDAP_OPT_X_TLS_NEVER;
  int err = ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqCert);
  if (err != LDAP_OPT_SUCCESS) {
    set_error(err);
    return false;
  }

  err = ldap_initialize(&ldap, uri.c_str());
  if (err != LDAP_SUCCESS) {
    set_error(err);
    return false;
  }

  int version = LDAP_VERSION3;
  err = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (err != LDAP_OPT_SUCCESS) {
    set_error(err);
    return false;
  }

  ldap_set_option(ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

  build_dn(user_name, dn_str, dn_str_len);

  return true;
}
}  // namespace alp

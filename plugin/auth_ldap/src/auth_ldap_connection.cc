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
#include "plugin/auth_ldap/include/auth_ldap_connection.h"
#include "plugin/auth_ldap/include/plugin_log.h"

// Forward declaration??
#define CR_AUTH_PLUGIN_ERROR 3
#define CR_AUTH_HANDSHAKE 2
#define CR_AUTH_USER_CREDENTIALS 1
#define CR_ERROR 0
#define CR_OK -1

namespace alp {
AuthLDAPConnection::AuthLDAPConnection(
    std::string server_host, unsigned int server_port, bool ssl, bool tls,
    std::string ca_path, std::string bind_user, std::string uid_attr,
    std::string user_name, std::string bind_pwd) {
  this->ldap = nullptr;
  if ((this->error = initiate(server_host, server_port, ssl, tls, ca_path)) ==
      CR_OK) {
    std::string bind_dn = getLDAPBind(bind_user, uid_attr, user_name);
    this->error = bind(bind_dn, bind_pwd);
  }
}

AuthLDAPConnection::AuthLDAPConnection(std::string server_host,
                                       unsigned int server_port, bool ssl,
                                       bool tls, std::string ca_path,
                                       std::string bind_dn,
                                       std::string bind_pwd) {
  this->ldap = nullptr;
  if ((this->error = initiate(server_host, server_port, ssl, tls, ca_path)) ==
      CR_OK) {
    this->error = bind(bind_dn, bind_pwd);
  }
}

AuthLDAPConnection::~AuthLDAPConnection() {
  if (this->ldap != nullptr) {
    ldap_unbind_ext_s(this->ldap, nullptr, nullptr);
  }
}

int AuthLDAPConnection::bind(std::string bind_dn, std::string bind_pwd) {
  if (bind_dn.empty() || bind_pwd.empty()) {
    // log_error("Error; trying to bind to an empty dn or password");
    return CR_AUTH_PLUGIN_ERROR;
  }

  struct berval *serverCreds;
  struct berval *userCreds =
      ber_str2bv(strdup(bind_pwd.c_str()), 0, 0, nullptr);

  int err = ldap_sasl_bind_s(this->ldap, bind_dn.c_str(), LDAP_SASL_SIMPLE,
                             userCreds, nullptr, nullptr, &serverCreds);
  if (err != LDAP_SUCCESS) {
    log_warn("Unsuccesful bind: ldap_sasl_bind_s %s", ldap_err2string(err));
    return CR_AUTH_USER_CREDENTIALS;
  }

  return CR_OK;
}

std::string AuthLDAPConnection::getLDAPBind(std::string bind_base_dn,
                                            std::string uid_attr,
                                            std::string user_name) {
  std::string str;
  if (bind_base_dn[0] == '+') {
    str = uid_attr;
    str.append("=").append(user_name).append(",");
    str.append(bind_base_dn.substr(1));
  } else {
    str = bind_base_dn;
  }

  return str;
}

std::string AuthLDAPConnection::getLDAPUri(std::string server_host,
                                           unsigned int server_port, bool ssl) {
  return std::string(ssl ? "ldaps://" : "ldap://")
      .append(server_host)
      .append(":")
      .append(std::to_string(server_port));
}

int AuthLDAPConnection::initiate(std::string server_host,
                                 unsigned int server_port, bool ssl, bool tls,
                                 std::string ca_path) {
  this->created_ts = std::time(nullptr);
  this->borrowed = false;

  if (server_host.empty()) {
    // log_error("ERROR: server_host is empty");
    return CR_AUTH_PLUGIN_ERROR;
  }

  int err;

  err = ldap_initialize(&(this->ldap),
                        getLDAPUri(server_host, server_port, ssl).c_str());
  if (err != LDAP_SUCCESS) {
    log_error("ERROR: ldap_initialize %s", ldap_err2string(err));
    return CR_AUTH_PLUGIN_ERROR;
  }

  int version = LDAP_VERSION3;
  err = ldap_set_option(this->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (err != LDAP_OPT_SUCCESS) {
    log_error("ERROR: ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) %s",
              ldap_err2string(err));
    return CR_AUTH_PLUGIN_ERROR;
  }

  ldap_set_option(this->ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

  if (ca_path.size() == 0) {
    int reqCert = LDAP_OPT_X_TLS_NEVER;
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqCert);
    if (err != LDAP_OPT_SUCCESS) {
      log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT) %s",
                ldap_err2string(err));
      return CR_AUTH_PLUGIN_ERROR;
    }
  } else {
    char *cca_path = strdup(ca_path.c_str());
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_CACERTFILE,
                          static_cast<void *>(cca_path));
    delete cca_path;
    if (err != LDAP_OPT_SUCCESS) {
      log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE) %s",
                ldap_err2string(err));
      return CR_AUTH_PLUGIN_ERROR;
    }
  }

  int new_ctx = 0;
  err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
  if (err != LDAP_OPT_SUCCESS) {
    log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_NEWCTX) %s",
              ldap_err2string(err));
    return CR_AUTH_PLUGIN_ERROR;
  }

  if (tls) {
    err = ldap_start_tls_s(this->ldap, nullptr, nullptr);
    if (err != LDAP_SUCCESS) {
      log_error("ERROR: ldap_start_tls_s %s", ldap_err2string(err));
      return CR_AUTH_PLUGIN_ERROR;
    }
  }

  return CR_OK;
}

}  // namespace alp

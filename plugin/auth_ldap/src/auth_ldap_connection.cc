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

#include <iostream>
#include <regex>

namespace alp {
AuthLDAPConnection::AuthLDAPConnection(std::string server_host,
                                       unsigned int server_port, bool ssl,
                                       bool tls, std::string ca_path,
                                       bool initial_bind, std::string bind_dn,
                                       std::string bind_pwd) {
  this->ldap = nullptr;
  if (initiate(server_host, server_port, ssl, tls, ca_path)) {
    if (initial_bind) {
      bind(bind_dn, bind_pwd);
    }
  }
}

AuthLDAPConnection::~AuthLDAPConnection() {
  if (this->ldap != nullptr) {
    ldap_unbind_ext_s(this->ldap, nullptr, nullptr);
  }
}

bool AuthLDAPConnection::bind(std::string bind_dn, std::string bind_pwd) {
  if (bind_dn.empty() || bind_pwd.empty()) {
    // log_error("Error; trying to bind to an empty dn or password");
    return false;
  }

  struct berval *serverCreds;
  struct berval *userCreds =
      ber_str2bv(strdup(bind_pwd.c_str()), 0, 0, nullptr);

  int err = ldap_sasl_bind_s(this->ldap, bind_dn.c_str(), LDAP_SASL_SIMPLE,
                             userCreds, nullptr, nullptr, &serverCreds);
  if (err != LDAP_SUCCESS) {
    log_warn("Unsuccesful bind: ldap_sasl_bind_s %s", ldap_err2string(err));
    return false;
  }

  return true;
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

bool AuthLDAPConnection::initiate(std::string server_host,
                                  unsigned int server_port, bool ssl, bool tls,
                                  std::string ca_path) {
  this->created_ts = std::time(nullptr);
  this->borrowed = false;

  if (server_host.empty()) {
    // log_error("ERROR: server_host is empty");
    return false;
  }

  int err = ldap_initialize(&(this->ldap),
                            getLDAPUri(server_host, server_port, ssl).c_str());
  if (err != LDAP_SUCCESS) {
    log_error("ERROR: ldap_initialize %s", ldap_err2string(err));
    return false;
  }

  int version = LDAP_VERSION3;
  err = ldap_set_option(this->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (err != LDAP_OPT_SUCCESS) {
    log_error("ERROR: ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) %s",
              ldap_err2string(err));
    return false;
  }

  ldap_set_option(this->ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

  if (ca_path.size() == 0) {
    int reqCert = LDAP_OPT_X_TLS_NEVER;
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqCert);
    if (err != LDAP_OPT_SUCCESS) {
      log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT) %s",
                ldap_err2string(err));
      return false;
    }
  } else {
    char *cca_path = strdup(ca_path.c_str());
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_CACERTFILE,
                          static_cast<void *>(cca_path));
    delete cca_path;
    if (err != LDAP_OPT_SUCCESS) {
      log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE) %s",
                ldap_err2string(err));
      return false;
    }
  }

  int new_ctx = 0;
  err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
  if (err != LDAP_OPT_SUCCESS) {
    log_error("ERROR: ldap_set_option(LDAP_OPT_X_TLS_NEWCTX) %s",
              ldap_err2string(err));
    return false;
  }

  if (tls) {
    err = ldap_start_tls_s(this->ldap, nullptr, nullptr);
    if (err != LDAP_SUCCESS) {
      log_error("ERROR: ldap_start_tls_s %s", ldap_err2string(err));
      return false;
    }
  }

  return true;
}

std::string AuthLDAPConnection::search_dn(std::string user_name,
                                          std::string user_search_attr,
                                          std::string base_dn) {
  std::string str;
  std::string filter = user_search_attr + "=" + user_name;

  LDAPMessage *res;
  char *attrs[] = {strdup("dn"), nullptr};
  struct timeval search_timeout;
  memset(&search_timeout, 0, sizeof(struct timeval));
  search_timeout.tv_sec = 5;
  int searchlimit = 1;
  int err = ldap_search_ext_s(
      this->ldap, base_dn.c_str() /* base */, LDAP_SCOPE_SUBTREE /*scope*/,
      filter.c_str() /*filter*/, attrs /*attrs*/, 0 /*attrsonly*/,
      nullptr /*serverctrls*/, nullptr /*clientctrls*/,
      &search_timeout /*timeout*/, searchlimit /*searchlimit*/,
      &res /*ldapmessage*/);
  if (err == LDAP_SUCCESS) {
    // Verify an entry was found
    if (ldap_count_entries(this->ldap, res) == 0) {
      log_warn("ldap_search_ext_s(%s, %s) returned no matching entries",
               base_dn.c_str(), filter.c_str());
      // Only free up res if there are no items
      ldap_msgfree(res);
      res = nullptr;
    } else {
      LDAPMessage *entry = ldap_first_entry(this->ldap, res);
      char *dn = ldap_get_dn(this->ldap, entry);
      log_debug("ldap_search_ext_s(%s, %s): %s", base_dn.c_str(),
                filter.c_str(), dn);
      str = dn;
      ldap_memfree(dn);
      ldap_memfree(entry);
    }
  } else {
    log_error("ERROR: ldap_search_ext_s(%s, %s) %s", base_dn.c_str(),
              filter.c_str(), ldap_err2string(err));
  }

  return str;
}

std::list<std::string> AuthLDAPConnection::search_groups(
    std::string user_name, std::string user_dn, std::string group_search_attr,
    std::string group_search_filter, std::string base_dn) {
  std::list<std::string> list;
  std::string filter = std::regex_replace(group_search_filter,
                                          std::regex("\\{UA\\}"), user_name);
  filter = std::regex_replace(filter, std::regex("\\{UD\\}"), user_dn);
  log_debug("search_groups() - filter: %s", filter.c_str());

  LDAPMessage *res;
  char *attrs[] = {strdup(group_search_attr.c_str()), nullptr};
  struct timeval search_timeout;
  memset(&search_timeout, 0, sizeof(struct timeval));
  search_timeout.tv_sec = 5;
  int err = ldap_search_ext_s(
      this->ldap, base_dn.c_str() /* base */, LDAP_SCOPE_SUBTREE /*scope*/,
      filter.c_str() /*filter*/, attrs /*attrs*/, 0 /*attrsonly*/,
      nullptr /*serverctrls*/, nullptr /*clientctrls*/,
      &search_timeout /*timeout*/, 0 /*searchlimit*/, &res /*ldapmessage*/);
  if (err == LDAP_SUCCESS) {
    // Verify an entry was found
    if (ldap_count_entries(this->ldap, res) == 0) {
      log_warn("ldap_search_ext_s(%s, %s) returned no matching entries",
               base_dn.c_str(), filter.c_str());
      // Only free up res if there are no items
      ldap_msgfree(res);
      res = nullptr;
    } else {
      LDAPMessage *entry = ldap_first_entry(this->ldap, res);
      const char *attribute;
      BerElement *ber;
      BerValue **vals;
      while (entry) {
        attribute = ldap_first_attribute(this->ldap, entry, &ber);
        while (attribute) {
          vals = ldap_get_values_len(this->ldap, entry, attribute);
          for (int pos = 0; pos < ldap_count_values_len(vals); pos++) {
            list.push_back(std::string(vals[pos]->bv_val));
            std::cerr << attribute << " " << pos << " " << vals[pos]->bv_val
                      << '\n';
          }
          ldap_value_free_len(vals);
          attribute = ldap_next_attribute(this->ldap, entry, ber);
        }
        ber_free(ber, 0);
        ldap_memfree(entry);
        entry = ldap_next_entry(this->ldap, entry);
      }
    }
  } else {
    log_error("ERROR: ldap_search_ext_s(%s, %s) %s", base_dn.c_str(),
              filter.c_str(), ldap_err2string(err));
  }

  return list;
}

}  // namespace alp

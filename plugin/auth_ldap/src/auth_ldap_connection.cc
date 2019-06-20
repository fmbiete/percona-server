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

namespace mysql {
namespace plugin {
namespace auth_ldap {
AuthLDAPConnection::AuthLDAPConnection(std::string server_host,
                                       unsigned int server_port, bool ssl,
                                       bool tls, std::string ca_path,
                                       bool initial_bind, std::string bind_dn,
                                       std::string bind_pwd) {
  this->ldap = nullptr;
  initiate(server_host, server_port, ssl, tls, ca_path);
  if (initial_bind) bind(bind_dn, bind_pwd, initial_bind);
}

AuthLDAPConnection::~AuthLDAPConnection() {
  if (this->ldap != nullptr) {
    ldap_unbind_ext_s(this->ldap, nullptr, nullptr);
  }
}

bool AuthLDAPConnection::bind(std::string bind_dn, std::string bind_pwd,
                              bool initial_bind) {
  if (bind_dn.empty() || bind_pwd.empty()) {
    if (!initial_bind)
      log_srv_error("ERROR; trying to bind to an empty dn or password");
    return false;
  }

  struct berval *serverCreds;
  struct berval *userCreds =
      ber_str2bv(strdup(bind_pwd.c_str()), 0, 0, nullptr);

  int err = ldap_sasl_bind_s(this->ldap, bind_dn.c_str(), LDAP_SASL_SIMPLE,
                             userCreds, nullptr, nullptr, &serverCreds);
  if (err != LDAP_SUCCESS) {
    std::stringstream log_stream;
    log_stream << "Unsuccesful bind: ldap_sasl_bind_s(" << bind_dn << ") "
               << ldap_err2string(err);
    log_srv_warn(log_stream.str());
    return false;
  }

  return true;
}

std::string AuthLDAPConnection::get_ldap_uri(std::string server_host,
                                             unsigned int server_port,
                                             bool ssl) {
  std::stringstream str_stream;
  str_stream << (ssl ? "ldaps://" : "ldap://") << server_host << ":"
             << server_port;
  return str_stream.str();
}

bool AuthLDAPConnection::initiate(std::string server_host,
                                  unsigned int server_port, bool ssl, bool tls,
                                  std::string ca_path) {
  this->created_ts = std::time(nullptr);
  this->borrowed = false;

  if (server_host.empty()) {
    // log_srv_error("ERROR: server_host is empty");
    return false;
  }

  int err = ldap_initialize(
      &(this->ldap), get_ldap_uri(server_host, server_port, ssl).c_str());
  if (err != LDAP_SUCCESS) {
    std::stringstream log_stream;
    log_stream << "ERROR: ldap_initialize " << ldap_err2string(err);
    log_srv_error(log_stream.str());
    return false;
  }

  int version = LDAP_VERSION3;
  err = ldap_set_option(this->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (err != LDAP_OPT_SUCCESS) {
    std::stringstream log_stream;
    log_stream << "ERROR: ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) "
               << ldap_err2string(err);
    log_srv_error(log_stream.str());
    return false;
  }

  ldap_set_option(this->ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

  ldap_set_option(this->ldap, LDAP_OPT_RESTART, LDAP_OPT_ON);

  if (ca_path.size() == 0) {
    int reqCert = LDAP_OPT_X_TLS_NEVER;
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqCert);
    if (err != LDAP_OPT_SUCCESS) {
      std::stringstream log_stream;
      log_stream << "ERROR: ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT) "
                 << ldap_err2string(err);
      log_srv_error(log_stream.str());
      return false;
    }
  } else {
    char *cca_path = strdup(ca_path.c_str());
    err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_CACERTFILE,
                          static_cast<void *>(cca_path));
    delete cca_path;
    if (err != LDAP_OPT_SUCCESS) {
      std::stringstream log_stream;
      log_stream << "ERROR: ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE) "
                 << ldap_err2string(err);
      log_srv_error(log_stream.str());
      return false;
    }
  }

  int new_ctx = 0;
  err = ldap_set_option(this->ldap, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
  if (err != LDAP_OPT_SUCCESS) {
    std::stringstream log_stream;
    log_stream << "ERROR: ldap_set_option(LDAP_OPT_X_TLS_NEWCTX) "
               << ldap_err2string(err);
    log_srv_error(log_stream.str());
    return false;
  }

  if (tls) {
    err = ldap_start_tls_s(this->ldap, nullptr, nullptr);
    if (err != LDAP_SUCCESS) {
      std::stringstream log_stream;
      log_stream << "ERROR: ldap_start_tls_s " << ldap_err2string(err);
      log_srv_error(log_stream.str());
      return false;
    }
  }

  return true;
}

bool AuthLDAPConnection::is_alive() {
  int id;
  return ldap_whoami(this->ldap, nullptr, nullptr, &id) == LDAP_SUCCESS;
}

std::string AuthLDAPConnection::search_dn(std::string user_name,
                                          std::string user_search_attr,
                                          std::string base_dn) {
  std::string str;
  std::stringstream log_stream;
  std::string filter = user_search_attr + "=" + user_name;

  log_stream << "search_dn(" << base_dn << ", " << filter << ")";
  log_srv_dbg(log_stream.str());
  log_stream.str("");

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
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << ") returned no matching entries";
      log_srv_warn(log_stream.str());
      log_stream.str("");
      // Only free up res if there are no items
      ldap_msgfree(res);
      res = nullptr;
    } else {
      LDAPMessage *entry = ldap_first_entry(this->ldap, res);
      char *dn = ldap_get_dn(this->ldap, entry);
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << "): " << dn;
      log_srv_dbg(log_stream.str());
      log_stream.str("");
      str = dn;
      ldap_memfree(dn);
      ldap_memfree(entry);
    }
  } else {
    log_stream << "ERROR: ldap_search_ext_s(" << base_dn << ", " << filter
               << ") " << ldap_err2string(err);
    log_srv_error(log_stream.str());
    log_stream.str("");
  }

  log_stream << "search_dn(" << base_dn << ", " << filter << ") = " << str;
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return str;
}

std::list<std::string> AuthLDAPConnection::search_groups(
    std::string user_name, std::string user_dn, std::string group_search_attr,
    std::string group_search_filter, std::string base_dn) {
  std::list<std::string> list;
  std::stringstream log_stream;
  std::string filter = std::regex_replace(group_search_filter,
                                          std::regex("\\{UA\\}"), user_name);
  filter = std::regex_replace(filter, std::regex("\\{UD\\}"), user_dn);
  log_stream << "search_groups() - filter: " << filter;
  log_srv_dbg(log_stream.str());
  log_stream.str("");

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
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << ") returned no matching entries";
      log_srv_warn(log_stream.str());
      log_stream.str("");
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
    log_stream << "ERROR: ldap_search_ext_s(" << base_dn << ", " << filter
               << ") " << ldap_err2string(err);
    log_srv_error(log_stream.str());
    log_stream.str("");
  }

  log_stream << "search_groups() = ";
  std::copy(list.begin(), list.end(),
            std::ostream_iterator<std::string>(log_stream, ","));
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return list;
}

}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql

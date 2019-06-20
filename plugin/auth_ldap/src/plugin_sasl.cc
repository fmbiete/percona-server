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

#include "plugin/auth_ldap/include/plugin_sasl.h"
#include "plugin/auth_ldap/include/auth_ldap_connection_pool.h"
#include "plugin/auth_ldap/include/plugin_common.h"
#include "plugin/auth_ldap/include/plugin_log.h"
#include "plugin/auth_ldap/include/plugin_variables.h"

#include <sasl/sasl.h>

#define MYSQL_SASL_SERVICE_NAME "ldap"
#define MYSQL_SASL_MECHANISM "SCRAM-SHA-1"

Ldap_logger *g_logger_server;

MYSQL_PLUGIN auth_ldap_sasl_plugin_info;

// Declaration to access the name of the SYS_VAR
struct SYS_VAR {
  MYSQL_PLUGIN_VAR_HEADER;
};

template <typename Copy_type>
void update_sysvar(THD *, SYS_VAR *var, void *var_ptr, const void *value) {
  // Update the value
  *(Copy_type *)var_ptr = *(Copy_type *)value;

  if (strcmp(var->name, "authentication_ldap_sasl_log_status") == 0)
    g_logger_server->set_log_level(static_cast<ldap_log_level>(log_status));
  else {
    connPool->reconfigure(init_pool_size, max_pool_size, STR_NULL(server_host),
                          server_port, ssl, tls, STR_NULL(bind_root_dn),
                          STR_NULL(bind_root_pwd), STR_NULL(ca_path));
    // connPool->debug_info();
  }
}

// Return true on success
bool _client_recv(MYSQL_PLUGIN_VIO *vio, char **data, unsigned int *len) {
  unsigned char *buf;
  int slen = 0;
  *data = nullptr;
  if ((slen = vio->read_packet(vio, &buf)) != -1) {
    *len = slen;
    *data = new char[*len];
    memcpy(*data, buf, *len);
    std::stringstream log_stream;
    log_stream << "_client_recv [" << *data << "]";
    log_srv_dbg(log_stream.str());
  } else {
    *len = 0;
  }
  return slen != -1;
}

// Return true on success
bool _client_send(MYSQL_PLUGIN_VIO *vio, const char *data, int len = 1) {
  std::stringstream log_stream;
  log_stream << "_client_send [" << data << "]";
  log_srv_dbg(log_stream.str());
  return vio->write_packet(vio, reinterpret_cast<const unsigned char *>(data),
                           len) == 0;
}

int _sasl_error(MYSQL_PLUGIN_VIO *vio, sasl_conn_t **conn, const char *msg,
                int err_code = SASL_OK, int ret_code = CR_AUTH_PLUGIN_ERROR) {
  std::stringstream log_stream;
  log_stream << msg;
  if (err_code != SASL_OK) {
    log_stream << " (" << err_code << ") "
               << sasl_errstring(err_code, nullptr, nullptr) << "["
               << sasl_errdetail(*conn) << "]";
  }
  log_srv_error(log_stream.str());
  if (conn != nullptr) {
    _client_send(vio, "N");
    sasl_dispose(conn);
  }

  return ret_code;
}

static int canonuser(sasl_conn_t *connection __attribute__((unused)),
                     void *context __attribute__((unused)), const char *input,
                     unsigned inputLength,
                     unsigned flags __attribute__((unused)),
                     const char *userRealm __attribute__((unused)),
                     char *output,
                     unsigned outputMaxLength __attribute__((unused)),
                     unsigned *outputLength) {
  // Tell SASL that the canonical username is the same as the
  // client-supplied username.
  memcpy(output, input, inputLength);
  *outputLength = inputLength;

  log_srv_dbg("canonuser()");
  log_srv_dbg(input);
  log_srv_dbg(output);

  return SASL_OK;
}

static int checkpass(sasl_conn_t *conn, void *context, const char *user,
                     const char *pass, unsigned passlen,
                     struct propctx *propctx) {
  log_srv_dbg("sasl_server_userdb_checkpass");
  return SASL_OK;
}

static int auth_ldap_sasl_init(MYSQL_PLUGIN plugin_info) {
  auth_ldap_sasl_plugin_info = plugin_info;
  // TODO: use my_mem
  g_logger_server = new Ldap_logger();
  g_logger_server->set_log_level(static_cast<ldap_log_level>(log_status));
  log_srv_dbg("Ldap_logger initialized");

  auth_ldap_common_init();

  log_srv_dbg("auth_ldap_sasl_init()");

  log_srv_dbg("Initializing SASL library");
  int sres = sasl_server_init(nullptr, MYSQL_SASL_SERVICE_NAME);
  if (sres != SASL_OK) {
    return _sasl_error(nullptr, nullptr, "ERROR: Initializing SASL library (server)",
                       sres);
  }
  sres = sasl_client_init(nullptr);
  if (sres != SASL_OK) {
    return _sasl_error(nullptr, nullptr, "ERROR: Initializing SASL library (client)", sres);
  }

  log_srv_dbg("Creating LDAP connection pool");
  connPool = new alp::AuthLDAPConnectionPool(
      init_pool_size, max_pool_size, STR_NULL(server_host), server_port, ssl,
      tls, STR_NULL(bind_root_dn), STR_NULL(bind_root_pwd), STR_NULL(ca_path));
  connPool->debug_info();

  log_srv_info("Plugin initialized");

  return 0;
}

static int auth_ldap_sasl_deinit(MYSQL_PLUGIN plugin_info
                                 __attribute__((unused))) {
  log_srv_dbg("auth_ldap_sasl_deinit()");

  log_srv_dbg("Cleaning up SASL");
  sasl_done();

  auth_ldap_common_deinit(connPool);

  delete g_logger_server;
  auth_ldap_sasl_plugin_info = nullptr;
  return 0;
}

int mpaldap_sasl_authenticate(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info) {
  log_srv_dbg("mpaldap_sasl_authenticate()");
  std::stringstream log_stream;
  sasl_conn_t *conn = nullptr;
  char *client_in = nullptr;
  unsigned int client_in_len;

  // FIXME: this is a TCP proxy, we don't need to understand SASL for the most part of this
  log_srv_dbg("c: received client initial request");
  log_srv_dbg("s: send mechanism to client");
  if (!_client_send(vio, MYSQL_SASL_MECHANISM, strlen(MYSQL_SASL_MECHANISM))) {
    return _sasl_error(vio, &conn,
                       "ERROR: Sending SASL mechanism list to client");
  }
  log_srv_dbg("p: creating SASL request to ldap server");
  sres = sasl_client_new(MYSQL_SASL_SERVICE_NAME, nullptr, nullptr, nullptr, nullptr, 0, &conn);
  if (sres != SASL_OK) {
    return _sasl_error(vio, &conn, "ERROR: creating SASL client to proxy requests", sres);
  }
  // TODO: security properties
  log_srv_dbg("p: create TCP connection to LDAP server");
  // TODO:
  log_srv_dbg("p: negotiate mechanism with ldap server");
  write_to_ldap(MYSQL_SASL_MECHANISM, strlen(MYSQL_SASL_MECHANISM));
  // Get and send
  log_srv_dbg("c: receive first packet");
  if (!_client_recv(vio, &client_in, &client_in_len)) {
    return _sasl_error(vio, &conn, "ERROR: Reading SASL first packet");
  }
  //n,a=user1,n=user1,r=q4W25ieI2tinTIYFgd0MPt4XaWP3GDN6
  log_srv_dbg("s: transform user name");
  // split string by ,
  std::vector<std::string> parts, subparts;
  boost::algorithm::split(parts, client_in, boost::is_any_of(","));
  std::string a = parts[1];
  boost::algorithm::split(subparts, a, boost::is_any_of("="));
  std::string user_name = subparts[1];
  std::string uid = get_uid();
  std::string n = parts[2];
  std::string nonce = parts[3];
  // common get uid
  // TODO:
  log_srv_dbg("s: rewrite first request");
  log_stream << "n,a=" << uid << ",n=" << uid << nonce;
  // TODO:
  log_srv_dbg("p: send first packet");
  // TODO:
  log_srv_dbg("p: receive first answer");
  // TODO:
  log_srv_dbg("s: send first answer");
  // N packets



  const char *server_out;
  unsigned int client_in_len, server_out_len;

  sasl_security_properties_t secprops;
  memset(&secprops, 0L, sizeof(secprops));
  secprops.maxbufsize = 2048;
  secprops.max_ssf = UINT_MAX;
  secprops.security_flags |= SASL_SEC_PASS_CREDENTIALS;

  log_srv_dbg("sasl_server_new");
  sasl_conn_t *conn = nullptr;
  // https://gitlab.oye.io/oyenet/mesos/blob/322cb8b77c0f27b135cae088281bc49f6a27ec01/src/authentication/cram_md5/authenticator.cpp
  // https://www.cyrusimap.org/sasl/sasl/developer/programming.html#common-section
  const sasl_callback_t callbacks[] = {
      {SASL_CB_CANON_USER, (int (*)()) & canonuser, nullptr},
      {SASL_CB_SERVER_USERDB_CHECKPASS, (int (*)()) & checkpass, nullptr},
      {SASL_CB_LIST_END, nullptr, nullptr}};
  int sres = sasl_server_new(MYSQL_SASL_SERVICE_NAME, nullptr, nullptr, nullptr,
                             nullptr, callbacks, 0, &conn);
  if (sres != SASL_OK) {
    return _sasl_error(vio, &conn, "ERROR: Creating SASL server connection",
                       sres);
  }

  /*
  sres = sasl_setprop(conn, SASL_SEC_PROPS, &secprops);
  if (sres != SASL_OK) {
    return _sasl_error(vio, &conn, "ERROR: Setting SASL security properties",
                       sres);
  }*/

  // https://www.cyrusimap.org/sasl/sasl/developer/programming.html#a-typical-interaction-from-the-server-s-perspective

  log_srv_dbg("force sasl mechanism");
  const char *chosenmech = MYSQL_SASL_MECHANISM;

  log_srv_dbg("send sasl mechanism");
  if (!_client_send(vio, MYSQL_SASL_MECHANISM, strlen(MYSQL_SASL_MECHANISM))) {
    return _sasl_error(vio, &conn,
                       "ERROR: Sending SASL mechanism list to client");
  }

  // log_srv_dbg("receive answer <sasl mechanism>");
  // char *chosenmech;
  // if (!_client_recv(vio, &chosenmech, &len)) {
  //   return _sasl_error(vio, &conn,
  //                      "ERROR: SASL mechanism not read from client");
  // }
  // if (strcmp(chosenmech, MYSQL_SASL_MECHANISM) != 0) {
  //   delete chosenmech;
  //   return _sasl_error(
  //       vio, &conn, "ERROR: SASL mechanism from client not supported by
  //       MySQL");
  // }

  log_srv_dbg("sasl_server_start");
  sres = sasl_server_start(conn, MYSQL_SASL_MECHANISM, nullptr, 0, &server_out,
                           &server_out_len);
  if (sres != SASL_OK && sres != SASL_CONTINUE) {
    return _sasl_error(vio, &conn, "ERROR: Starting SASL server process", sres);
  }

  log_srv_dbg("sasl receive first packet");
  if (!_client_recv(vio, &client_in, &client_in_len)) {
    return _sasl_error(vio, &conn, "ERROR: Reading SASL first packet");
  }

  log_srv_dbg("sasl process first packet");
  sres = sasl_server_step(conn, client_in, client_in_len, &server_out,
                          &server_out_len);
  if (sres != SASL_OK && sres != SASL_CONTINUE) {
    return _sasl_error(vio, &conn, "ERROR: Executing SASL step", sres);
  }

  log_srv_dbg("send second packet");
  _client_send(vio, server_out, server_out_len);

  return CR_OK;

  log_srv_dbg("sasl_server_start");
  if (client_in) {
    sres = sasl_server_start(conn, chosenmech, client_in, client_in_len,
                             &server_out, &server_out_len);
  } else {
    sres = sasl_server_start(conn, chosenmech, nullptr, 0, &server_out,
                             &server_out_len);
  }
  // const char *data;
  // if (buf[0] == 'y') {
  // log_srv_dbg("initial packet found, reading next");
  // delete buf;
  // if (!_client_recv(vio, &buf, &len)) {
  // return _sasl_error(vio, &conn,
  // "ERROR: Reading SASL first packet after discard one");
  // }

  // sres = sasl_server_start(conn, chosenmech, buf, len, &data, &len);
  // } else {
  // sres = sasl_server_start(conn, chosenmech, nullptr, 0, &data, &len);
  // }

  // TODO: can we cast *buf to sasl_interact_t *
  // struct id, result, len

  if (sres != SASL_OK && sres != SASL_CONTINUE) {
    return _sasl_error(vio, &conn, "ERROR: Starting SASL server process", sres);
  }

  while (sres == SASL_CONTINUE) {
    log_srv_dbg("loop send sasl continue");
    _client_send(vio, "C");
    if (server_out) {
      _client_send(vio, server_out, server_out_len);
    }

    // if (data) {
    // if(!(_client_send(vio, "C") || _client_send(vio, data, true, len))) {
    // return _sasl_error(vio, &conn, "ERROR: Sending SASL continue packet with
    // data");
    // }
    // } else {
    // if(!(_client_send(vio, "C") || _client_send(vio, "", true, 0))) {
    // return _sasl_error(vio, &conn, "ERROR: Sending SASL continue packet
    // without data");
    // }

    log_srv_dbg("loop receive sasl data");
    _client_recv(vio, &client_in, &client_in_len);
    // delete buf;
    // if (!_client_recv(vio, &buf, &len)) {
    // return _sasl_error(vio, &conn,
    // "ERROR: Receiving SASL packet after continue");
    // }

    log_srv_dbg("loop sasl_server_step");
    // sres = sasl_server_step(conn, buf, len, &data, &len);
    sres = sasl_server_step(conn, client_in, client_in_len, &server_out,
                            &server_out_len);
    if (sres != SASL_OK && sres != SASL_CONTINUE) {
      return _sasl_error(vio, &conn, "ERROR: Executing SASL step", sres);
    }
  }

  log_srv_dbg("sasl client communication complete");

  log_srv_dbg("processing sasl data");
  const char *userid;
  sres = sasl_getprop(conn, SASL_USERNAME,
                      reinterpret_cast<const void **>(&userid));
  if (sres != SASL_OK) {
    return _sasl_error(vio, &conn, "ERROR: getting SASL_USERNAME", sres);
  }
  log_stream << "Username [" << userid << "]";
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  log_srv_dbg("authenticate");
  // int ldapexample_sasl_interact(LDAP * ld, unsigned flags, void * defaults,
  // void * sin) Copy defaults to sin
  //   err = ldap_sasl_interactive_bind_s
  //       (
  //          ld,                         // LDAP                    * ld
  //          NULL,                       // const char              * dn
  //          config.auth.saslmech,       // const char              * mechs
  //          NULL,                       // LDAPControl             * sctrls[]
  //          NULL,                       // LDAPControl             * cctrls[]
  //          LDAP_SASL_QUIET,            // unsigned                  flags
  //          ldapexample_sasl_interact,  // LDAP_SASL_INTERACT_PROC * interact
  //          &ptr /* TODO: pass here *buf */                // void * defaults
  //       );
  // if (err != LDAP_SUCCESS)

  // int do_interact(LDAP * ld, unsigned flags, void *defaults, void *in) {
  //   sasl_interact_t *interact = in;
  //   char *sasl_defaults = (char *)defaults;
  //   const char *dflt = interact->defresult;
  //   dflt = sasl_defaults;
  //   interact->result = (dflt && *dflt) ? dflt : "";
  //   interact->len = strlen(interact->result);
  //   return LDAP_SUCCESS;
  // }

  // TODO: where is the password stored??
  char *password = nullptr;
  // https://github.com/percona/percona-server/blob/8.0/libmysql/authentication_ldap/auth_ldap_sasl_client.cc

  int res = auth_ldap_common_authenticate_user(
      vio, info, password, connPool, user_search_attr, group_search_attr,
      group_search_filter, bind_base_dn);

  log_srv_dbg("send sasl authentication result");

  res = CR_OK;
  if (!_client_send(vio, res == CR_OK ? "O" : "N")) {
    return _sasl_error(vio, &conn, "ERROR: Sending SASL last packet");
  }

  log_srv_dbg("SASL negotiation complete");

  sasl_dispose(&conn);

  return res;
}

// Plugin declaration
struct st_mysql_auth mpaldap_sasl_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,  // int interface_version
    "authentication_ldap_sasl_client",       // const char *client_auth_plugin
    &mpaldap_sasl_authenticate,                  // authentication function
    &auth_ldap_common_generate_auth_string_hash,  // generate_authentication_string
    &auth_ldap_common_validate_auth_string_hash,  // validate_authentication_string
    &auth_ldap_common_set_salt,                   // set_salt
    0UL,  // const unsigned long authentication_flags
    nullptr};

mysql_declare_plugin(auth_ldap_sasl) {
  MYSQL_AUTHENTICATION_PLUGIN,           /* plugin type */
      &mpaldap_sasl_handler,                 /* type-specific descriptor */
      MPALDAP_SASL_PLUGIN_NAME,              /* plugin name */
      "Francisco Miguel Biete Banon",    /* author */
      "LDAP SASL authentication plugin", /* description */
      PLUGIN_LICENSE_GPL,                /* license type */
      &auth_ldap_sasl_init,              /* init function */
      &auth_ldap_sasl_deinit,            /* deinit function */
      nullptr,                           /* no check function */
      0x0100,                            /* version = 1.0 */
      nullptr,                           /* no status variables */
      mpaldap_sysvars,                       /* system variables */
      nullptr                            /* no reserved information */
#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
      ,
      0 /* no flags */
#endif
}
mysql_declare_plugin_end;

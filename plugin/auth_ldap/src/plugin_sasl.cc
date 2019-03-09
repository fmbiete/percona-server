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

#define SASL_SERVICE_NAME "ldap"

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

int log_sasl_error(MYSQL_PLUGIN_VIO *vio, const char *msg, int err_code,
                   bool b_sasl_send_n, bool b_sasl_dispose, sasl_conn_t **conn,
                   int result) {
  std::stringstream log_stream;
  log_stream << msg;
  if (err_code != SASL_OK)
    log_stream << " " << sasl_errstring(err_code, nullptr, nullptr);
  log_srv_error(log_stream.str());
  if (b_sasl_send_n) {
    vio->write_packet(
        vio, static_cast<const unsigned char *>(static_cast<const void *>("N")),
        1);  // trying to tell the sasl client to end
  }

  if (b_sasl_dispose) sasl_dispose(conn);
  return result;
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
  int res = sasl_server_init(NULL, SASL_SERVICE_NAME);
  if (res != SASL_OK) {
    return log_sasl_error(nullptr, "ERROR: Initializing SASL library", res,
                          false, false, nullptr, 1);
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

int alp_sasl_authenticate(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info) {
  log_srv_dbg("alp_sasl_authenticate()");

  // Create sasl server
  sasl_conn_t *conn;
  log_srv_dbg("Creating SASL server connection");
  int res = sasl_server_new(SASL_SERVICE_NAME, nullptr, nullptr, nullptr,
                            nullptr, nullptr, 0, &conn);
  if (res != SASL_OK) {
    return log_sasl_error(vio, "ERROR: Creating SASL server connection", res,
                          false, false, nullptr, CR_AUTH_PLUGIN_ERROR);
  }

  // TODO: Channel binding?

  const char *data;
  int len, count;
  log_srv_dbg("Creating SASL list mechanism");
  res = sasl_listmech(conn, nullptr, nullptr, " ", nullptr, &data,
                      (unsigned int *)&len, &count);
  if (res != SASL_OK) {
    return log_sasl_error(vio, "ERROR: Creating SASL list mechanism", res,
                          false, true, &conn, CR_AUTH_PLUGIN_ERROR);
  }
  std::stringstream log_stream;
  log_stream << "SASL mechanisms " << count << " [" << data << "]";
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  // send list
  if (vio->write_packet(vio, (const unsigned char *)data, len) != 0) {
    return log_sasl_error(vio,
                          "ERROR: writing SASL list mechanism to MySQL socket",
                          SASL_OK, false, true, &conn, CR_AUTH_PLUGIN_ERROR);
  }

  unsigned char *chosenmech;
  if (vio->read_packet(vio, &chosenmech) < 0) {
    return log_sasl_error(vio, "ERROR: reading SASL mechanism chosen by client",
                          SASL_OK, true, true, &conn, CR_AUTH_PLUGIN_ERROR);
  }

  log_stream << "SASL mechanism chosen by client " << chosenmech;
  log_srv_dbg(log_stream.str());
  log_stream.str("");
  log_srv_dbg()

  // read first parameter
  unsigned char *buf;
  if ((len = vio->read_packet(vio, &buf)) < 0) {
    return log_sasl_error(vio, "ERROR: reading SASL parameter", SASL_OK, true,
                          true, &conn, CR_AUTH_PLUGIN_ERROR);
  }

  if (buf[0] == 'Y') {
    // Extra packet in the initial request, discard and read the next
    if ((len = vio->read_packet(vio, &buf)) < 0) {
      return log_sasl_error(vio, "ERROR: reading SASL parameter loop", SASL_OK,
                            true, true, &conn, CR_AUTH_PLUGIN_ERROR);
    }
    res = sasl_server_start(
        conn, static_cast<const char *>(static_cast<void *>(chosenmech)),
        static_cast<const char *>(static_cast<void *>(buf)), len, &data,
        static_cast<unsigned int *>(static_cast<void *>(&len)));
  } else {
    res = sasl_server_start(
        conn, static_cast<const char *>(static_cast<void *>(chosenmech)),
        nullptr, 0, &data,
        static_cast<unsigned int *>(static_cast<void *>(&len)));
  }

  if (res != SASL_OK && res != SASL_CONTINUE) {
    return log_sasl_error(vio, "ERROR: starting SASL server", res, true, true,
                          &conn, CR_AUTH_PLUGIN_ERROR);
  }

  while (res == SASL_CONTINUE) {
    if (vio->write_packet(
            vio,
            static_cast<const unsigned char *>(static_cast<const void *>("C")),
            1) != 0) {
      return log_sasl_error(vio, "ERROR: writing SASL continue", SASL_OK, true,
                            true, &conn, CR_AUTH_PLUGIN_ERROR);
    }

    if ((len = vio->read_packet(vio, &buf)) < 0) {
      return log_sasl_error(vio, "ERROR: reading SASL parameter loop", SASL_OK,
                            true, true, &conn, CR_AUTH_PLUGIN_ERROR);
    }

    log_srv_dbg("read ");
    log_srv_dbg(static_cast<const char *>(static_cast<void *>(buf)));

    res = sasl_server_step(conn,
                           static_cast<const char *>(static_cast<void *>(buf)),
                           len, &data, (unsigned int *)&len);
    if (res != SASL_OK && res != SASL_CONTINUE) {
      return log_sasl_error(vio, "ERROR: step SASL server loop", res, true,
                            true, &conn, CR_AUTH_PLUGIN_ERROR);
    }
  }

  if (res != SASL_OK) {
    return log_sasl_error(vio, "ERROR: ending loop SASL ", res, true, true,
                          &conn, CR_AUTH_PLUGIN_ERROR);
  }

  // TODO: authenticate here??
  // TODO: where are the username and password stored??
  char *password = nullptr;
  // https://github.com/percona/percona-server/blob/8.0/libmysql/authentication_ldap/auth_ldap_sasl_client.cc

  res = auth_ldap_common_authenticate_user(vio, info, password, connPool,
                                           user_search_attr, group_search_attr,
                                           group_search_filter, bind_base_dn);

  if (vio->write_packet(
          vio,
          static_cast<const unsigned char *>(
              static_cast<const void *>(res == CR_OK ? "O" : "N")),
          1) != 0) {
    return log_sasl_error(vio, "ERROR: writing OK to SASL client", SASL_OK,
                          true, true, &conn, CR_AUTH_PLUGIN_ERROR);
  }
  log_srv_dbg("SASL negotiation complete");

  sasl_dispose(&conn);

  return CR_OK;
}

// Plugin declaration
struct st_mysql_auth alp_sasl_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,  // int interface_version
    "authentication_ldap_sasl_client",       // const char *client_auth_plugin
    &alp_sasl_authenticate,                  // authentication function
    &auth_ldap_common_generate_auth_string_hash,  // generate_authentication_string
    &auth_ldap_common_validate_auth_string_hash,  // validate_authentication_string
    &auth_ldap_common_set_salt,                   // set_salt
    0UL,  // const unsigned long authentication_flags
    nullptr};

mysql_declare_plugin(auth_ldap_sasl) {
  MYSQL_AUTHENTICATION_PLUGIN,           /* plugin type */
      &alp_sasl_handler,                 /* type-specific descriptor */
      ALP_SASL_PLUGIN_NAME,              /* plugin name */
      "Francisco Miguel Biete Banon",    /* author */
      "LDAP SASL authentication plugin", /* description */
      PLUGIN_LICENSE_GPL,                /* license type */
      &auth_ldap_sasl_init,              /* init function */
      &auth_ldap_sasl_deinit,            /* deinit function */
      nullptr,                           /* no check function */
      0x0100,                            /* version = 1.0 */
      nullptr,                           /* no status variables */
      alp_sysvars,                       /* system variables */
      nullptr                            /* no reserved information */
#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
      ,
      0 /* no flags */
#endif
}
mysql_declare_plugin_end;

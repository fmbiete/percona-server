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

//#include "plugin/auth_ldap/include/auth_ldap_simple.h"
#include "plugin/auth_ldap/include/auth_ldap_connection.h"
#include "plugin/auth_ldap/include/auth_ldap_connection_pool.h"
#include "plugin/auth_ldap/include/plugin_common.h"
#include "plugin/auth_ldap/include/plugin_log.h"
#include "plugin/auth_ldap/include/plugin_simple.h"
#include "plugin/auth_ldap/include/plugin_variables.h"

MYSQL_PLUGIN auth_ldap_simple_plugin_info;

template <typename Copy_type>
void update_sysvar(THD *, SYS_VAR *, void *tgt, const void *save) {
  *(Copy_type *)tgt = *(Copy_type *)save;
  connPool->reconfigure(init_pool_size, max_pool_size, STR_NULL(server_host),
                        server_port, ssl, tls, STR_NULL(bind_root_dn),
                        STR_NULL(bind_root_pwd), STR_NULL(ca_path));
}

static int auth_ldap_simple_init(MYSQL_PLUGIN plugin_info) {
  set_alp_log_status(log_status);
  auth_ldap_common_init();
  log_debug("auth_ldap_simple_init()");

  log_debug("Creating LDAP connection pool");
  log_debug("init_pool_size %d", init_pool_size);
  log_debug("max_pool_size %d", max_pool_size);
  log_debug("server_host %s", server_host);
  log_debug("server_port %d", server_port);
  log_debug("tls %d", tls);
  log_debug("bind_root_dn %s", bind_root_dn);
  log_debug("bind_root_pwd %s", bind_root_pwd);
  log_debug("ca_path %s", ca_path);
  log_debug("auth_method_name %s", auth_method_name);
  connPool = new alp::AuthLDAPConnectionPool(
      init_pool_size, max_pool_size, STR_NULL(server_host),
      server_port, ssl, tls, STR_NULL(bind_root_dn),
      STR_NULL(bind_root_pwd),
      STR_NULL(ca_path));

  auth_ldap_simple_plugin_info = plugin_info;
  log_info("Plugin initialized");

  return 0;
}

static int auth_ldap_simple_deinit(MYSQL_PLUGIN plugin_info
                                   __attribute__((unused))) {
  log_debug("auth_ldap_simple_deinit()");

  auth_ldap_common_deinit(connPool);

  auth_ldap_simple_plugin_info = nullptr;
  return 0;
}

int alp_simple_authenticate(MYSQL_PLUGIN_VIO *vio,
                            MYSQL_SERVER_AUTH_INFO *info) {
  log_debug("alp_simple_authenticate()");

  return auth_ldap_common_authenticate_user(connPool, vio, info, server_host,
                                            server_port, ssl, tls, ca_path,
                                            user_search_attr, bind_base_dn);
}

// Plugin declaration
struct st_mysql_auth alp_simple_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,  // int interface_version
    "dialog",                                // const char *client_auth_plugin
    &alp_simple_authenticate,                // authentication function
    &auth_ldap_common_generate_auth_string_hash,  // generate_authentication_string,
    &auth_ldap_common_validate_auth_string_hash,  // validate_authentication_string,
    &auth_ldap_common_set_salt,                   // set_salt,
    0UL,  // const unsigned long authentication_flags
    nullptr};

mysql_declare_plugin(auth_ldap_simple) {
  MYSQL_AUTHENTICATION_PLUGIN,             /* plugin type */
      &alp_simple_handler,                 /* type-specific descriptor */
      ALP_SIMPLE_PLUGIN_NAME,              /* plugin name */
      "Francisco Miguel Biete Banon",      /* author */
      "LDAP Simple authentication plugin", /* description */
      PLUGIN_LICENSE_GPL,                  /* license type */
      &auth_ldap_simple_init,              /* init function */
      &auth_ldap_simple_deinit,            /* deinit function */
      nullptr,                             /* no check function */
      0x0100,                              /* version = 1.0 */
      nullptr,                             /* no status variables */
      alp_sysvars,                         /* system variables */
      nullptr                              /* no reserved information */
#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
      ,
      0 /* no flags */
#endif
}
mysql_declare_plugin_end;

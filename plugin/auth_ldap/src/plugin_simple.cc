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

#include "plugin/auth_ldap/include/auth_ldap_simple.h"
#include "plugin/auth_ldap/include/plugin_common.h"
#include "plugin/auth_ldap/include/plugin_simple.h"

#include "mysql/components/services/log_builtins.h"

MYSQL_PLUGIN auth_ldap_simple_plugin_info;

static int auth_ldap_simple_init(MYSQL_PLUGIN plugin_info) {
  auth_ldap_simple_plugin_info = plugin_info;
  return 0;
}

// Static var for System variables
static char *authentication_ldap_simple_bind_base_dn;
static char *authentication_ldap_simple_server_host;
static unsigned int authentication_ldap_simple_server_port;

int alp_simple_authenticate(MYSQL_PLUGIN_VIO *vio,
                            MYSQL_SERVER_AUTH_INFO *info) {
  DBUG_ENTER("alp_simple_authenticate");
  alp::AuthLDAPSimple *obj =
      new alp::AuthLDAPSimple(authentication_ldap_simple_server_host,
                              authentication_ldap_simple_server_port,
                              authentication_ldap_simple_bind_base_dn);
  return auth_ldap_authenticate_user(obj, vio, info);
}

// System Variables
static MYSQL_SYSVAR_STR(
    alp_simple_dn, authentication_ldap_simple_bind_base_dn,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
    "For Simple LDAP authentication, the base distinguished name (DN)",
    nullptr /* check */, nullptr /* update */, nullptr /* default */);
static MYSQL_SYSVAR_STR(alp_simple_host, authentication_ldap_simple_server_host,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
                        "For Simple LDAP authentication, the LDAP server host",
                        nullptr /* check */, nullptr /* update */,
                        nullptr /* default */);
static MYSQL_SYSVAR_UINT(
    alp_simple_port, authentication_ldap_simple_server_port,
    PLUGIN_VAR_RQCMDARG,
    "For Simple LDAP authentication, the LDAP server TCP/IP port number",
    nullptr /* check */, nullptr /* update */, 389 /* default */,
    1 /*minimum */, 32376 /* maximum */, 0 /* blocksize */);

static SYS_VAR *alp_simple_sysvars[] = {MYSQL_SYSVAR(alp_simple_dn),
                                        MYSQL_SYSVAR(alp_simple_host),
                                        MYSQL_SYSVAR(alp_simple_port), nullptr};

// Plugin declaration
struct st_mysql_auth alp_simple_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,  // int interface_version
    "mysql_clear_password",                  // const char *client_auth_plugin
    &alp_simple_authenticate,
    nullptr,  // generate_authentication_string,
    nullptr,  // validate_authentication_string,
    nullptr,  // set_salt,
    0UL,      // const unsigned long authentication_flags
    nullptr};


mysql_declare_plugin(auth_ldap_simple) {
  MYSQL_AUTHENTICATION_PLUGIN,             /* plugin type */
      &alp_simple_handler,                 /* type-specific descriptor */
      ALP_SIMPLE_PLUGIN_NAME,              /* plugin name */
      "Francisco Miguel Biete Banon",      /* author */
      "LDAP Simple authentication plugin", /* description */
      PLUGIN_LICENSE_GPL,                  /* license type */
      &auth_ldap_simple_init,                             /* no init function */
      nullptr,                             /* no deinit function */
      nullptr,                             /* no check function */
      0x0100,                              /* version = 1.0 */
      nullptr,                             /* no status variables */
      alp_simple_sysvars,                  /* no system variables */
      nullptr                              /* no reserved information */
//#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
      ,
      0 /* no flags */
//#endif
}
mysql_declare_plugin_end;

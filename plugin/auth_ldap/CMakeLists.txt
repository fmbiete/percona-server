# Copyright (c) 2019, Francisco Miguel Biete Banon. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
IF(WITH_LDAP)
  INCLUDE (CheckLibraryExists)
  CHECK_LIBRARY_EXISTS(ldap ldap_initialize "" HAVE_LDAP)

  IF(NOT HAVE_LDAP)
  	MESSAGE(FATAL_ERROR "Required LDAP dev library not found. Please install LDAP development files!")
  ENDIF(NOT HAVE_LDAP)

  IF(HAVE_LDAP)
    SET(ALP_SOURCES_SASL
      ../../libmysql/authentication_ldap/log_client.cc
      src/plugin_common.cc
      src/plugin_sasl.cc
      src/auth_ldap_connection.cc
      src/auth_ldap_connection_pool.cc
    )
    SET(ALP_SOURCES_SIMPLE
      ../../libmysql/authentication_ldap/log_client.cc
      src/plugin_common.cc
      src/plugin_simple.cc
      src/auth_ldap_connection.cc
      src/auth_ldap_connection_pool.cc
    )
    ### Configuration ###
    ADD_DEFINITIONS(-DLOG_COMPONENT_TAG="auth_ldap")

    INCLUDE_DIRECTORIES(SYSTEM ${BOOST_PATCHES_DIR} ${BOOST_INCLUDE_DIR})

    MYSQL_ADD_PLUGIN(authentication_ldap_sasl ${ALP_SOURCES_SASL} LINK_LIBRARIES ldap MODULE_ONLY MODULE_OUTPUT_NAME "authentication_ldap_sasl")
    MYSQL_ADD_PLUGIN(authentication_ldap_simple ${ALP_SOURCES_SIMPLE} LINK_LIBRARIES ldap MODULE_ONLY MODULE_OUTPUT_NAME "authentication_ldap_simple")

    IF(UNIX)
      IF(INSTALL_MYSQLTESTDIR)
        INSTALL(DIRECTORY tests/mtr/ DESTINATION ${INSTALL_MYSQLTESTDIR}/suite/auth_ldap COMPONENT Test)
      ENDIF(INSTALL_MYSQLTESTDIR)
    ENDIF(UNIX)

  ENDIF(HAVE_LDAP)
ENDIF(WITH_LDAP)

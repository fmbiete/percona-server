/* Copyright (c) 2014, 2018, Oracle and/or its affiliates. All rights reserved.
   Copyright (c) 2019 Francisco Miguel Biete Banon. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA
*/

#include <array>

#include "mysql/components/my_service.h"
#include "mysql/components/services/registry.h"
#include "mysql/components/services/udf_registration.h"
#include "mysql/service_plugin_registry.h"

#include "plugin/mail_udf/include/plugin.h"
#include "plugin/mail_udf/include/udf_descriptor.h"
#include "plugin/mail_udf/include/udf_mail_send.h"
#include "plugin/mail_udf/include/udf_registration.h"

/* The UDFs we will register. */
static std::array<udf_descriptor, 1> udfs = {{udf_mail_send()}};

bool register_udfs() {
  bool error = false;
  SERVICE_TYPE(registry) *plugin_registry = mysql_plugin_registry_acquire();

  if (plugin_registry == nullptr) {
    error = true;
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "ERROR acquiring plugin registry");
    return error;
  }

  {
    /* We open a new scope so that udf_registrar is (automatically) destroyed
       before plugin_registry. */
    my_service<SERVICE_TYPE(udf_registration)> udf_registrar("udf_registration",
                                                             plugin_registry);
    if (udf_registrar.is_valid()) {
      for (udf_descriptor const &udf : udfs) {
        error = udf_registrar->udf_register(
            udf.name, udf.result_type, udf.main_function, udf.init_function,
            udf.deinit_function);
        if (error) {
          LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "ERROR registering udf ",
                       udf.name);
          break;
        }
      }

      if (error) {
        int was_present;
        for (udf_descriptor const &udf : udfs) {
          // Don't care about errors since we are already erroring out.
          udf_registrar->udf_unregister(udf.name, &was_present);
        }
      }
    } else {
      error = true;
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "ERROR acquiring udf registration service");
    }
  }

  mysql_plugin_registry_release(plugin_registry);

  return error;
}

bool unregister_udfs() {
  bool error = false;

  SERVICE_TYPE(registry) *plugin_registry = mysql_plugin_registry_acquire();

  if (plugin_registry == nullptr) {
    error = true;
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "ERROR acquiring registry");
    return error;
  }

  {
    /* We open a new scope so that udf_registrar is (automatically) destroyed
       before plugin_registry. */
    my_service<SERVICE_TYPE(udf_registration)> udf_registrar("udf_registration",
                                                             plugin_registry);
    if (udf_registrar.is_valid()) {
      int was_present;
      for (udf_descriptor const &udf : udfs) {
        // Don't care about the functions not being there.
        error = error || udf_registrar->udf_unregister(udf.name, &was_present);
      }
    } else {
      error = true;
    }

    if (error) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "ERROR acquiring udf registration service");
    }
  }

  mysql_plugin_registry_release(plugin_registry);

  return error;
}

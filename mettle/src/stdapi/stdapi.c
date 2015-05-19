/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file stdapi.c
 */

#include "fs/file.c"
#include "net/config.c"
#include "sys/config.c"

void tlv_register_stdapi(struct mettle *m, struct tlv_dispatcher *td)
{
	tlv_dispatcher_add_handler(td, "stdapi_fs_getwd", fs_getwd, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_ls", fs_ls, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_stat", fs_stat, m);

	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_interfaces",
			net_config_get_interfaces, m);
	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_routes",
			net_config_get_routes, m);

	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getenv",
			sys_config_getenv, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getuid",
			sys_config_getuid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_sysinfo",
			sys_config_sysinfo, m);
}

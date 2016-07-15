/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file stdapi.c
 */

#include "mettle.h"
#include "fs/file.c"
#include "net/config.c"
#include "net/resolve.c"
#include "sys/config.c"
#include "sys/process.c"

void tlv_register_stdapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	file_register_handlers(m);

	net_config_register_handlers(m);
	net_resolve_register_handlers(m);

	// Sys
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getenv", sys_config_getenv, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getuid", sys_config_getuid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_sysinfo", sys_config_sysinfo, m);

	// Process
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_processes", sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_attach", sys_process_attach, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_close", sys_process_close, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_execute", sys_process_execute, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_kill", sys_process_kill, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_processes", sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_getpid", sys_process_getpid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_info", sys_process_get_info, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_wait", sys_process_wait, m);
}

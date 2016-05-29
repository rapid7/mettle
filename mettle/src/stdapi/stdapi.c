/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file stdapi.c
 */

#include "mettle.h"
#include "fs/file.c"
#include "net/config.c"
#include "sys/config.c"
#include "sys/process.c"

#define add_handler(name) \
	tlv_dispatcher_add_handler(td, "stdapi_stdapi_" name, m)

void tlv_register_stdapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	tlv_dispatcher_add_handler(td, "stdapi_fs_chdir", fs_chdir, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_delete_file", fs_delete_file, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_expand_path", fs_expand_path, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_file_move", fs_file_move, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_getwd", fs_getwd, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_mkdir", fs_mkdir, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_ls", fs_ls, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_separator", fs_separator, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_stat", fs_stat, m);

	struct channel_callbacks cbs = {
		.new_cb = file_new_cb,
		.read_cb = file_read_cb,
		.write_cb = file_write_cb,
		.eof_cb = file_eof_cb,
		.free_cb = file_free_cb,
	};
	channelmgr_add_channel_type(cm, "stdapi_fs_file", &cbs);

	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_interfaces", net_config_get_interfaces, m);
	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_routes", net_config_get_routes, m);

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

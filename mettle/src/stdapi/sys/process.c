/**
 * Copyright 2015 Rapid7
 * @brief System Process API
 * @file process.c
 */

#include <libgen.h>
#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

static struct tlv_packet *
get_process_info(sigar_t *sigar, sigar_pid_t pid)
{
	sigar_proc_state_t pstate;
	int status = sigar_proc_state_get(sigar, pid, &pstate);
	if (status != SIGAR_OK) {
		log_debug("error: %d (%s) proc_state(%d)",
			status, sigar_strerror(sigar, status), pid);
		return NULL;
	}

	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_PROCESS_GROUP, 0);

	p = tlv_packet_add_u32(p, TLV_TYPE_PID, pid);
	p = tlv_packet_add_u32(p, TLV_TYPE_PARENT_PID, pstate.ppid);
	p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_NAME,
			(pstate.name[0] == '/') ? basename(pstate.name) : pstate.name);

	/*
	 * the path data comes from another sigar struct; try to get it for each
	 * process and add the data if it is available to us
	 */
	sigar_proc_exe_t procexe;
	status = sigar_proc_exe_get(sigar, pid, &procexe);
	if (status == SIGAR_OK) {
		p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_PATH, dirname(procexe.name));
	} else {
		p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_PATH, "");
	}

	p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_ARCH_NAME, procexe.arch);

	/*
	 * the username data comes from another sigar struct; try to get it for each
	 * process and add the data if it is available to us
	 */
	sigar_proc_cred_name_t uname_data;
	status = sigar_proc_cred_name_get(sigar, pid, &uname_data);
	if (status == SIGAR_OK) {
		p = tlv_packet_add_str(p, TLV_TYPE_USER_NAME, uname_data.user);
	} else {
		log_debug("error: %d (%s) proc_state(%d)",
			status, sigar_strerror(sigar, status), pid);
	}

	return p;
}

static inline int sigar_to_tlv_status(int rc)
{
	return rc == SIGAR_OK ? TLV_RESULT_SUCCESS : TLV_RESULT_FAILURE;
}

/*
 * use sigar to create a process list and add the data to the response packet
 */
struct tlv_packet *
sys_process_get_processes(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	sigar_t *sigar = mettle_get_sigar(m);

	sigar_proc_list_t processes;
	int status = sigar_proc_list_get(sigar, &processes);

	if (status != SIGAR_OK) {
		log_debug("proc_list error: %d (%s)",
			   status, sigar_strerror(sigar, status));
		return tlv_packet_response_result(ctx, sigar_to_tlv_status(status));
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	for (int i = 0; i < processes.number; i++) {
		struct tlv_packet *proc_info = get_process_info(sigar, processes.data[i]);
		if (proc_info) {
			p = tlv_packet_add_child(p, proc_info);
		}
	}
	sigar_proc_list_destroy(sigar, &processes);

	return p;
}

/*
 * return a packet with a process handle if the OS is Windows-based if the OS
 * is not windows based, return ERROR_NOT_SUPPORTED should be a wrapper for the
 * open_process method in sigar
 */
struct tlv_packet *
sys_process_attach(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * close a process handle if the OS is Windows-based and the pid provided is
 * not the meterpreter pid if the OS is not windows-based, (?) No equivalent
 * sigar method
 */
struct tlv_packet *
sys_process_close(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * Starts a process on any OS Multiple configuration options, including pipes,
 * ptys, create suspended, etc
 */
struct tlv_packet *
sys_process_execute(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

struct tlv_packet *
sys_process_kill(struct tlv_handler_ctx *ctx)
{
	uint32_t pid;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid)) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	int status = sigar_proc_kill(pid, 9);
	if (status != SIGAR_OK) {
		log_debug("sigar_proc_kill failed to kill pid %d; returned status %d",
			pid, status);
	}
	return tlv_packet_response_result(ctx, sigar_to_tlv_status(status));
}

struct tlv_packet *
sys_process_getpid(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	sigar_t *sigar = mettle_get_sigar(m);

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_u32(p, TLV_TYPE_PID, sigar_pid_get(sigar));
}

struct tlv_packet *
sys_process_get_info(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	sigar_t *sigar = mettle_get_sigar(m);

	uint32_t pid;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid)) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	return get_process_info(sigar, pid);
}

/*
 * wrapper for windows WaitForSingleObject()
 * and 'nix waitpid()
 */
struct tlv_packet *sys_process_wait(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

void sys_process_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

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

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
	struct mettle *m = ctx->arg;
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * Handlers registered with the channel manager to send data to the process manager
 */
ssize_t sys_process_read(struct channel *c, char *buf, size_t len)
{
	ssize_t rc = channel_dequeue(c, buf, len);
	if (channel_get_ctx(c) == NULL && channel_queue_len(c) < 1) {
		channel_shutdown(c);
	}
	return rc;
}

ssize_t sys_process_write(struct channel *c, char *buf, size_t len)
{
	struct process *p = channel_get_ctx(c);
	return process_write(p, buf, len);
}

int sys_process_free(struct channel *c)
{
	struct process *p = channel_get_ctx(c);
	return process_kill(p);
}

/*
 * Handlers registered with the process manager to send data to the channel manager
 */
static void process_channel_exit_cb(struct process *p, int exit_status, void *arg)
{
	struct channel *c = arg;
	channel_set_ctx(c, NULL);
}

static void process_channel_read_cb(struct buffer_queue *queue, void *arg)
{
	struct channel *c = arg;
	size_t len = buffer_queue_len(queue);
	void *buf = malloc(len);
	if (buf) {
		buffer_queue_remove(queue, buf, len);
		channel_enqueue(c, buf, len);
		free(buf);
	}
}

struct tlv_packet *
sys_process_execute(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channelmgr *cm = mettle_get_channelmgr(m);
	struct procmgr *pm = mettle_get_procmgr(m);
	char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_PROCESS_PATH);
	char *args = tlv_packet_get_str(ctx->req, TLV_TYPE_PROCESS_ARGUMENTS);
	uint32_t flags = 0;

	tlv_packet_get_u32(ctx->req, TLV_TYPE_PROCESS_FLAGS, &flags);

	log_debug("process_new: %s %s 0x%08x", path, args, flags);

	struct process_options opts = {
		.process_name = path,
		.args = args,
		.env = NULL,
		.cwd = NULL,
		.user = NULL,
	};

	struct process *p = process_create(pm, path, &opts);
	if (p == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) {
		struct channel *c = channelmgr_channel_new(cm, "process");
		if (c == NULL) {
			process_kill(p);
			return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
		}

		channel_set_ctx(c, p);
		ctx->channel = c;
		ctx->channel_id = channel_get_id(c);

		process_set_callbacks(p,
		    process_channel_read_cb,
		    process_channel_read_cb,
		    process_channel_exit_cb, c);
	}
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}


void sys_process_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_processes", sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_attach", sys_process_attach, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_close", sys_process_close, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_execute", sys_process_execute, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_kill", sys_process_kill, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_processes", sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_getpid", sys_process_getpid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_get_info", sys_process_get_info, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_process_wait", sys_process_wait, m);

	struct channel_callbacks cbs = {
		.read_cb = sys_process_read,
		.write_cb = sys_process_write,
		.free_cb = sys_process_free,
	};
	channelmgr_add_channel_type(cm, "process", &cbs);
}

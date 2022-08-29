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
#include "command_ids.h"
#include "process.h"
#include "permission.h"

static struct tlv_packet *
get_process_info(sigar_t *sigar, sigar_pid_t pid)
{
	sigar_proc_state_t pstate;
	int status = sigar_proc_state_get(sigar, pid, &pstate);
	if (status != SIGAR_OK) {
		log_debug("error: %d (%s) proc_state(%lu)",
			status, sigar_strerror(sigar, status), (unsigned long)pid);
		return NULL;
	}

	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_PROCESS_GROUP, 0);

	p = tlv_packet_add_u32(p, TLV_TYPE_PID, pid);
	p = tlv_packet_add_u32(p, TLV_TYPE_PARENT_PID, pstate.ppid);

#ifdef __linux__
		/*
		 * for linux hosts, attempt to check if arguments can be obtained and if
		 * not wrap the process name in brackets like `ps` and the other
		 * meterpreters do
		 */
		sigar_proc_args_t pargs;
		status = sigar_proc_args_get(sigar, pid, &pargs);
		if (status != SIGAR_OK) {
			log_debug("error: %d (%s) proc_args(%lu)",
				status, sigar_strerror(sigar, status), (unsigned long) pid);
			return NULL;
		}
		if (pargs.number == 0) {
			p = tlv_packet_add_fmt(p, TLV_TYPE_PROCESS_NAME,
				"[%s]", pstate.name);
		} else {
			p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_NAME,
				(pstate.name[0] == '/') ? basename(pstate.name) : pstate.name);
		}
		sigar_proc_args_destroy(sigar, &pargs);
#else
		p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_NAME,
			(pstate.name[0] == '/') ? basename(pstate.name) : pstate.name);
#endif

	/*
	 * the path data comes from another sigar struct; try to get it for each
	 * process and add the data if it is available to us
	 */
	sigar_proc_exe_t procexe;
	status = sigar_proc_exe_get(sigar, pid, &procexe);
	if (status == SIGAR_OK) {
		p = tlv_packet_add_str(p, TLV_TYPE_PROCESS_PATH, procexe.name);
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
		log_debug("error: %d (%s) proc_state(%lu)",
			status, sigar_strerror(sigar, status), (unsigned long)pid);
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
	bool inherit;
	uint32_t pid;
	uint32_t perms;
	uint32_t real_perms = 0;
	struct tlv_packet *p = NULL;

	tlv_packet_get_bool(ctx->req, TLV_TYPE_INHERIT, &inherit);
	if(inherit)
	{
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	tlv_packet_get_u32(ctx->req, TLV_TYPE_PROCESS_PERMS, &perms);
	real_perms |= PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
	if(perms != PROCESS_READ && perms != real_perms)
	{
		log_debug("Requested unsupported permissions\n");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid);
	if(pid == 0)
	{
		uint32_t self_pid = getpid();
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_u32(p, TLV_TYPE_PID, self_pid);
		p = tlv_packet_add_u32(p, TLV_TYPE_HANDLE, self_pid);
		return p;
	}

	p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	p = tlv_packet_add_u32(p, TLV_TYPE_PID, pid);

	uint64_t handle = pid;
	p = tlv_packet_add_u64(p, TLV_TYPE_HANDLE, handle);

	return p;
}

struct tlv_packet *
sys_process_close(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct procmgr *pm = mettle_get_procmgr(m);

	uint64_t pid;
	if (tlv_packet_get_u64(ctx->req, TLV_TYPE_HANDLE, &pid)) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}
	int rc = process_kill_by_pid(pm, pid);
	return tlv_packet_response_result(ctx,
			rc == 0 ? TLV_RESULT_SUCCESS : TLV_RESULT_FAILURE);
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

struct channelmgr_ctx {
	struct channelmgr *cm;
	uint32_t channel_id;
	bool eof;
};

/*
 * Handlers registered with the channel manager to send data to the process manager
 */
ssize_t sys_process_read(struct channel *c, void *buf, size_t len)
{
	ssize_t rc = channel_dequeue(c, buf, len);
	if (rc > 0) {
		log_debug("read %zd bytes for channel", rc);
	}
	if (channel_get_ctx(c) == NULL && channel_queue_len(c) < 1) {
		channel_shutdown(c);
	}
	return rc;
}

ssize_t sys_process_write(struct channel *c, void *buf, size_t len)
{
	struct process *p = channel_get_ctx(c);
	return process_write(p, buf, len);
}

int sys_process_free(struct channel *c)
{
	struct process *proc = channel_get_ctx(c);
	return process_kill(proc);
}

/*
 * Handlers registered with the process manager to send data to the channel manager
 */
static void process_channel_exit_cb(struct process *p, int exit_status, void *arg)
{
	struct channelmgr_ctx *cm_ctx = arg;
	struct channel *c = channelmgr_channel_by_id(cm_ctx->cm, cm_ctx->channel_id);
	cm_ctx->eof = true;
	if (c) {
		if (channel_get_interactive(c)) {
			channel_send_close_request(c);
			free(cm_ctx);
		} else {
			channel_set_eof(c);
		}
	}
}

static void process_channel_read_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct channelmgr_ctx *cm_ctx = arg;
	struct channel *c = channelmgr_channel_by_id(cm_ctx->cm, cm_ctx->channel_id);
	if (!c) {
		return;
	}
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
	size_t exe_len;
	unsigned char *in_mem_exe = tlv_packet_get_raw(ctx->req, TLV_TYPE_VALUE_DATA, &exe_len);
	uint32_t flags = 0;

	tlv_packet_get_u32(ctx->req, TLV_TYPE_PROCESS_FLAGS, &flags);

	struct process_options opts = {
		.process_name = path,
		.args = args,
		.flags = 0
	};

	if (strchr(path, '$') != NULL || strchr(path, '%') != NULL) {
		opts.flags |= PROCESS_CREATE_SUBSHELL;
	}

	if (args && (strchr(args, '$') != NULL || strchr(args, '%') != NULL)) {
		opts.flags |= PROCESS_CREATE_SUBSHELL;
	}

	if (flags & PROCESS_EXECUTE_FLAG_SUBSHELL) {
		opts.flags |= PROCESS_CREATE_SUBSHELL;
	}

	if (flags & PROCESS_EXECUTE_FLAG_PTY) {
		opts.flags |= PROCESS_EXECUTE_FLAG_PTY;
	}

	log_debug("process_new: %s %s 0x%08x", path, args, flags);

	struct process *p;
	if (in_mem_exe != NULL && exe_len != 0) {
		log_debug("process_new: got %zd byte executable to run in memory", exe_len);
		opts.flags = PROCESS_CREATE_REFLECT;
		p = process_create_from_executable_buf(pm, in_mem_exe, &opts);
	} else {
		p = process_create_from_executable(pm, path, &opts);
	}

	if (p == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) {
		struct channelmgr_ctx *cm_ctx = calloc(1, sizeof *ctx);
		struct channel *c = channelmgr_channel_new(cm, "process");
		if (c == NULL || cm_ctx == NULL) {
			process_kill(p);
			free(cm_ctx);
			return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
		}

		channel_set_ctx(c, p);
		ctx->channel = c;
		cm_ctx->cm = cm;
		cm_ctx->channel_id = ctx->channel_id = channel_get_id(c);

		process_set_callbacks(p,
			process_channel_read_cb,
			process_channel_read_cb,
			process_channel_exit_cb, cm_ctx);
	}

	struct tlv_packet *resp = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	resp = tlv_packet_add_u32(resp, TLV_TYPE_PID, process_get_pid(p));
	resp = tlv_packet_add_u64(resp, TLV_TYPE_PROCESS_HANDLE, process_get_pid(p));
	return resp;
}

void sys_process_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_GET_PROCESSES, sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_ATTACH, sys_process_attach, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_CLOSE, sys_process_close, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_EXECUTE, sys_process_execute, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_KILL, sys_process_kill, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_GET_PROCESSES, sys_process_get_processes, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_GETPID, sys_process_getpid, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_GET_INFO, sys_process_get_info, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_WAIT, sys_process_wait, m);
#ifndef _WIN32
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_SET_TERM_SIZE, sys_process_set_term_size, m);
#endif

	struct channel_callbacks cbs = {
		.read_cb = sys_process_read,
		.write_cb = sys_process_write,
		.free_cb = sys_process_free,
	};
	channelmgr_add_channel_type(cm, "process", &cbs);
}

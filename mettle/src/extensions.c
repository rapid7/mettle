/**
 * Copyright 2017 Rapid7
 * @brief Extension management/handling
 * @file extensions.c
 */

#include "log.h"
#include "mettle.h"
#include "process.h"
#include "tlv.h"
#include "uthash.h"
        
#include <mettle.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// hash of all extension commands which points to extension to send to
struct extension_data
{
	char *command;
	struct process *proc;
	UT_hash_handle hh;
};

struct extmgr
{
	struct extension_data *extensions;
};

static struct extension_data *extension_data_new(const char *command, struct process *process)
{
	struct extension_data *data = calloc(1, sizeof(*data));
	if (data)
	{
		data->command = strdup(command);
		data->proc = process;
	}
	return data;
}

ssize_t extension_write(struct process *p,  void *buf, size_t len)
{
	return process_write(p, buf, len);
}

static struct tlv_packet *tlv_send_to_extension(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct extension_data *ed = NULL;

	// Lookup the extension we need to forward this onto.
	HASH_FIND_STR(mettle_get_extmgr(m)->extensions, ctx->method, ed);
	if (ed == NULL)
	{
		log_error("TLV method request for command '%s' failed to locate an associated extension",
				ctx->method);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	// Send the TLV along.
        extension_write(ed->proc, ctx->req, tlv_packet_len(ctx->req));
        return NULL;
}

static void register_extension_commands(struct mettle *m,
		struct process *p, void *buf, size_t len)
{
	char *cmds = malloc(len + 1);
	strncpy(cmds, (char *)buf, len);
	cmds[len] = '\0';
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	char *cmd = strtok(cmds, "\n");
	do
	{
		// Store extension info in hash
		struct extmgr *em = mettle_get_extmgr(m);
		struct extension_data *extension_data = extension_data_new(cmd, p);
		HASH_ADD_KEYPTR(hh, em->extensions, extension_data->command, \
				strlen(extension_data->command), extension_data);
		tlv_dispatcher_add_handler(td, cmd, tlv_send_to_extension, m);
	} while ((cmd = strtok(NULL, "\n")));
	process_set_extension_ready(p);
	free(cmds);
	free(buf);
}

static void extension_exit_cb(struct process *p, int exit_status, void *arg)
{
	struct mettle *m = (struct mettle *)arg;
}

static void extension_read_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct mettle *m = (struct mettle *)arg;
	size_t len = buffer_queue_len(queue);
	void *buf = malloc(len);
	if (buf) {
		buffer_queue_remove(queue, buf, len);
		if (process_get_extension_ready(p)) {
			struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
			tlv_dispatcher_enqueue_response(td, (struct tlv_packet *)buf);
		} else {
			register_extension_commands(m, p, buf, len);
		}
	}
}

static void extension_err_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct mettle *m = (struct mettle *)arg;
	size_t len = buffer_queue_len(queue);
	char *buf = malloc(len + 1);
	if (buf) {
		buffer_queue_remove(queue, (void *)buf, len);
		buf[len] = '\0';
		log_info("logged: %s", buf);
	}
}

int extension_start(struct mettle *m, const char *full_path,
	unsigned char *bin_image, size_t bin_image_len, const char* args)
{
	int ret_val = -1;
	struct procmgr *pm = mettle_get_procmgr(m);
	struct process_options opts = {
		.process_name = full_path,
		.args = args,
		.env = NULL,
		.cwd = NULL,
		.user = NULL,
	};

	struct process *p = process_create(pm, full_path, bin_image, bin_image_len, &opts);
	if (p == NULL) {
		log_error("Failed to start extension '%s'", full_path);
		goto done;
	}

	process_set_callbacks(p,
		extension_read_cb,
		extension_err_cb,
		extension_exit_cb, m);

	ret_val = 0;

done:
	return ret_val;
}

void extmgr_free(struct extmgr *mgr)
{
	if (mgr->extensions) {
		struct extension_data *extension, *tmp;
		HASH_ITER(hh, mgr->extensions, extension, tmp) {
			free(extension->command);
			HASH_DEL(mgr->extensions, extension);
			free(extension);
		}
	}
	free(mgr);
}

struct extmgr *extmgr_new()
{
	return calloc(1, sizeof(struct extmgr));
}

/**
 * Copyright 2017 Rapid7
 * @brief Extension management/handling
 * @file extensions.c
 */

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "mettle.h"
#include "process.h"
#include "tlv.h"
#include "uthash.h"

struct extension_process {
	struct mettle *m;
	struct process *p;
	int ready;
};

/*
 * Hash of all extension commands which points to extension to send to
 */
struct extension_data {
	char *command;
	struct extension_process *ep;
	UT_hash_handle hh;
};

struct extmgr
{
	struct extension_data *extensions;
};

static struct extension_data *extension_data_new(const char *command, struct extension_process *ep)
{
	struct extension_data *data = calloc(1, sizeof(*data));
	if (data) {
		data->command = strdup(command);
		data->ep = ep;
	}
	return data;
}

static struct tlv_packet *tlv_send_to_extension(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct extension_data *ed = NULL;

	/*
	 * Lookup the extension we need to forward this onto.
	 */
	HASH_FIND_STR(mettle_get_extmgr(m)->extensions, ctx->method, ed);
	if (ed == NULL) {
		log_error("TLV method request for command '%s' failed to locate an associated extension",
				ctx->method);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	/*
	 * Send the TLV along.
	 */
	process_write(ed->ep->p, ctx->req, tlv_packet_len(ctx->req));
	return NULL;
}

static void register_extension_commands(struct extension_process *ep,
	void *buf, size_t len)
{
	char *cmds = NULL;
	static char *cmds_previous = NULL;

	size_t cmds_copy_offset = 0;
	if (cmds_previous) {
		cmds = malloc(strlen(cmds_previous) + len + 1);
		strncpy(cmds, cmds_previous, strlen(cmds_previous));
		cmds_copy_offset = strlen(cmds_previous);
	} else {
		cmds = malloc(len + 1);
	}
	strncpy(&cmds[cmds_copy_offset], (char *)buf, len);
	len += cmds_copy_offset;
	cmds[len] = '\0';
	if (strcmp(&cmds[len-2], "\n\n")) {
		/*
		 * Did not receive the full list of commands yet.
		 * Save what we have for now until we get the whole thing.
		 */
		free(cmds_previous);
		cmds_previous = cmds;
		goto done_free_buf;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(ep->m);
	char *cmd = strtok(cmds, "\n");
	do {
		/*
		 * Store extension info in hash
		 */
		struct extmgr *em = mettle_get_extmgr(ep->m);
		struct extension_data *extension_data = extension_data_new(cmd, ep);
		HASH_ADD_KEYPTR(hh, em->extensions, extension_data->command, \
				strlen(extension_data->command), extension_data);
		tlv_dispatcher_add_handler(td, cmd, tlv_send_to_extension, ep);
	} while ((cmd = strtok(NULL, "\n")));

	ep->ready = 1;
	free(cmds_previous);
	free(cmds);

done_free_buf:
	free(buf);
}

static void extension_exit_cb(struct process *p, int exit_status, void *arg)
{
	struct extension_process *ep = arg;
	free(ep);
}

static void extension_read_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct extension_process *ep = arg;
	size_t len = buffer_queue_len(queue);
	void *buf = malloc(len);
	if (buf) {
		buffer_queue_remove(queue, buf, len);
		if (ep->ready) {
			struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(ep->m);
			tlv_dispatcher_enqueue_response(td, (struct tlv_packet *)buf);
		} else {
			register_extension_commands(ep, buf, len);
		}
	}
}

static void extension_err_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct extension_process *ep = arg;
	size_t len = buffer_queue_len(queue);
	char *buf = malloc(len + 1);
	if (buf) {
		buffer_queue_remove(queue, (void *)buf, len);
		buf[len] = '\0';
		if (buf[len-1] == '\n') {
			// remove newlines which were appended by log_XXX()
			buf[len-1] = '\0';
#ifdef _WIN32
			if (buf[len-2] == '\r') {
				// remove CRs which were appended by log_XXX()
				buf[len-2] = '\0';
			}
#endif
		}
		log_info("extension logged: %s", buf);
	}
}

static int extension_start(struct mettle *m, const char *full_path,
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

	struct extension_process *ep = calloc(1, sizeof(*ep));
	if (ep == NULL) {
		return -1;
	}

	if (bin_image) {
		ep->p = process_create_from_binary_image(pm, bin_image, bin_image_len, &opts, 0);
	} else {
		ep->p = process_create_from_executable(pm, full_path, &opts, 0);
	}
	if (ep->p == NULL) {
		log_error("Failed to start extension '%s'", full_path);
		free(ep);
		goto done;
	}
	ep->m = m;

	process_set_callbacks(ep->p,
		extension_read_cb,
		extension_err_cb,
		extension_exit_cb, ep);

	ret_val = 0;

done:
	return ret_val;
}

int extension_start_executable(struct mettle *m, const char *full_path,
	const char* args)
{
	return extension_start(m, full_path, NULL, 0, args);
}

int extension_start_binary_image(struct mettle *m, const char *name,
	unsigned char *bin_image, size_t bin_image_len, const char* args)
{
	return extension_start(m, name, bin_image, bin_image_len, args);
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

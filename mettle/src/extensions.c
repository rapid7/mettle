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
#include "command_ids.h"
#include "extensions.h"
#include "uthash.h"

/*
 * Hash of all extension commands which points to extension to send to
 */
struct extension_data {
	uint32_t command_id;
	struct extension_process *ep;
	UT_hash_handle hh;
};

struct extmgr
{
	struct extension_data *extensions;
};

static struct extension_data *extension_data_new(uint32_t command_id, struct extension_process *ep)
{
	struct extension_data *data = calloc(1, sizeof(*data));
	if (data) {
		data->command_id = command_id;
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
	HASH_FIND_INT(mettle_get_extmgr(m)->extensions, &ctx->command_id, ed);
	if (ed == NULL) {
		log_error("TLV method request for command_id '%u' failed to locate an associated extension",
				ctx->command_id);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	/*
	 * Send the TLV along.
	 */
	process_write(ed->ep->p, ctx->req, tlv_packet_len(ctx->req));
	return NULL;
}

static void extension_register_commands(struct extension_process *ep, struct tlv_packet *p) {
	struct tlv_iterator i = {
		.packet = p,
		.value_type = TLV_TYPE_UINT
	};
	size_t len;
	uint32_t result;
	uint32_t command_id;
	uint32_t *pcommand_id;

	if (tlv_packet_get_u32(p, TLV_TYPE_RESULT, &result)) {
		return;
	}

	if (result != TLV_RESULT_SUCCESS) {
		return;
	}

	while ((pcommand_id = tlv_packet_iterate(&i, &len))) {
		command_id = ntohl(*pcommand_id);
		if (command_id == COMMAND_ID_CORE_LOADLIB) {
			// Make sure extensions are not accidentally trying to register CORE_LOADLIB
			continue;
		}
		struct extmgr *em = mettle_get_extmgr(ep->m);
		struct extension_data *ed = extension_data_new(command_id, ep);
		HASH_ADD_INT(em->extensions, command_id, ed);
		struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(ep->m);
		tlv_dispatcher_add_handler(td, command_id, tlv_send_to_extension, ep->m);
	}
	return;
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
		struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(ep->m);
		struct tlv_packet *p = (struct tlv_packet *)buf;

		uint32_t command_id = 0;
		if (!ep->ready) {
			if (!((tlv_packet_get_u32(p, TLV_TYPE_COMMAND_ID, &command_id) == 0) && (command_id == COMMAND_ID_CORE_LOADLIB))) {
				return;
			}
			extension_register_commands(ep, p);
			ep->ready = true;
		}
		tlv_dispatcher_enqueue_response(td, p);
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

		/*
		 * Remove trailing whitespace
		 */
		char *end = &buf[len - 1];
		while (isspace(*end)) *end-- = '\0';

		log_info("extension logged: %s", buf);
	}
}

static struct extension_process * extension_start(struct mettle *m, const char *full_path,
	const unsigned char *bin_image, size_t bin_image_len, const char* args)
{
	struct procmgr *pm = mettle_get_procmgr(m);
	struct process_options opts = {
		.process_name = full_path,
		.args = args,
	};

	struct extension_process *ep = calloc(1, sizeof(*ep));
	if (ep == NULL) {
		return NULL;
	}

	if (bin_image) {
		ep->p = process_create_from_binary_image(pm, bin_image, bin_image_len, &opts);
	} else {
		ep->p = process_create_from_executable(pm, full_path, &opts);
	}
	if (ep->p == NULL) {
		log_error("Failed to start extension '%s'", full_path);
		free(ep);
		ep = NULL;
		goto done;
	}
	ep->m = m;

	process_set_callbacks(ep->p,
		extension_read_cb,
		extension_err_cb,
		extension_exit_cb, ep);

done:
	return ep;
}

struct extension_process * extension_start_executable(struct mettle *m, const char *full_path,
	const char* args)
{
	return extension_start(m, full_path, NULL, 0, args);
}

struct extension_process * extension_start_binary_image(struct mettle *m, const char *name,
	const unsigned char *bin_image, size_t bin_image_len, const char* args)
{
	return extension_start(m, name, bin_image, bin_image_len, args);
}

void extmgr_free(struct extmgr *mgr)
{
	if (mgr->extensions) {
		struct extension_data *extension, *tmp;
		HASH_ITER(hh, mgr->extensions, extension, tmp) {
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

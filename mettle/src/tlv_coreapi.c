/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "log.h"
#include "tlv.h"

#include <mettle.h>

static struct tlv_packet *machine_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_MACHINE_ID, mettle_get_fqdn(m));
}

static void add_method(const char *method, void *arg)
{
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_str(*p, TLV_TYPE_STRING, method);
}

static struct tlv_packet *enumextcmd(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	const char *extension = tlv_packet_get_str(ctx->req, TLV_TYPE_STRING);
	if (extension == NULL) {
		return NULL;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(td, extension, add_method, &p);
	return p;
}

static struct tlv_packet *core_shutdown(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

	void (*nada) (void) = NULL;
	nada();

	return p;
}

static struct tlv_packet *core_channel_open(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channelmgr *cm = mettle_get_channelmgr(m);

	char *channel_type = tlv_packet_get_str(ctx->req, TLV_TYPE_CHANNEL_TYPE);
	if (channel_type == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel *c = channelmgr_channel_new(cm, channel_type);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	if (cbs->new_cb) {
		if (cbs->new_cb(ctx, c) == -1) {
			channelmgr_channel_free(cm, c);
			return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
		}
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_SUCCESS);
	} else {
		return cbs->new_async_cb(ctx);
	}
}

static struct channel * get_channel_by_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channelmgr *cm = mettle_get_channelmgr(m);

	uint32_t channel_id;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_CHANNEL_ID, &channel_id)) {
		return NULL;
	}
	ctx->channel = channelmgr_channel_by_id(cm, channel_id);
	return ctx->channel;
}

static struct tlv_packet *core_channel_eof(struct tlv_handler_ctx *ctx)
{
	struct channel *c = get_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	struct tlv_packet *p;
	if (cbs->eof_cb) {
		p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_bool(p, TLV_TYPE_BOOL, cbs->eof_cb(channel_get_ctx(c)));
	} else {
		p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}
	return p;

}

static struct tlv_packet *core_channel_read(struct tlv_handler_ctx *ctx)
{
	struct channel *c = get_channel_by_id(ctx);
	if (c == NULL) {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}

	uint32_t len = 0;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &len) == -1) {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	if (cbs->read_cb) {
		char *buf = calloc(1, len);
		if (buf == NULL) {
			return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
		}

		ssize_t bytes_read = cbs->read_cb(channel_get_ctx(c), buf, len);
		struct tlv_packet *p;
		if (bytes_read > 0) {
			p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_SUCCESS);
			p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, bytes_read);
		} else {
			p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
		}
		free(buf);
		return p;

	} else if (cbs->read_async_cb) {
		return cbs->new_async_cb(ctx);
	} else {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}
}

static struct tlv_packet *core_channel_write(struct tlv_handler_ctx *ctx)
{
	struct channel *c = get_channel_by_id(ctx);
	if (c == NULL) {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}

	uint32_t len = 0;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &len) == -1) {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}


	struct channel_callbacks *cbs = channel_get_callbacks(c);

	if (cbs->write_cb) {
		size_t buf_len = 0;
		char *buf = tlv_packet_get_raw(ctx->req, TLV_TYPE_CHANNEL_DATA, &buf_len);
		if (buf == NULL) {
			return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
		}

		ssize_t bytes_written = cbs->write_cb(channel_get_ctx(c), buf, len);
		struct tlv_packet *p;
		if (bytes_written > 0) {
			p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_SUCCESS);
			p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, bytes_written);
		} else {
			p = channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
		}
		free(buf);
		return p;

	} else if (cbs->write_async_cb) {
		return cbs->new_async_cb(ctx);
	} else {
		return channel_tlv_packet_response_result(c, ctx, TLV_RESULT_FAILURE);
	}
}

void tlv_register_coreapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "core_enumextcmd", enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", machine_id, m);
	tlv_dispatcher_add_handler(td, "core_shutdown", core_shutdown, m);
	tlv_dispatcher_add_handler(td, "core_channel_open", core_channel_open, m);
	tlv_dispatcher_add_handler(td, "core_channel_eof", core_channel_eof, m);
	tlv_dispatcher_add_handler(td, "core_channel_read", core_channel_read, m);
	tlv_dispatcher_add_handler(td, "core_channel_write", core_channel_write, m);
	tlv_dispatcher_add_handler(td, "core_channel_close", core_channel_write, m);
}

/**
 * Copyright 2016 Rapid7
 * @brief Network Channel API
 * @file channel.c
 */

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "network_server.h"
#include "tlv.h"
#include "util.h"

static int tcp_server_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	uint32_t port = 0;
	struct mettle *m = ctx->arg;

	const char *host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);

	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_PORT, &port) == -1) {
		log_error("no port specified");
		return -1;
	}

	return 0;
}

static ssize_t tcp_server_read(struct channel *c, void *buf, size_t len)
{
	return 0;
}

static ssize_t tcp_server_write(struct channel *c, void *buf, size_t len)
{
	return 0;
}

static int tcp_server_free(struct channel *c)
{
	struct network_server *nc = channel_get_ctx(c);
	if (nc) {
		channel_set_ctx(c, NULL);
	}
	return 0;
}

void net_server_register_handlers(struct mettle *m)
{
	struct channelmgr *cm = mettle_get_channelmgr(m);

	struct channel_callbacks tcp_server_cbs = {
		.new_cb = tcp_server_new,
		.read_cb = tcp_server_read,
		.write_cb = tcp_server_write,
		.free_cb = tcp_server_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_net_tcp_server", &tcp_server_cbs);
}


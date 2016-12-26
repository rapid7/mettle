/**
 * Copyright 2016 Rapid7
 * @brief Network Channel API
 * @file channel.c
 */

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "network_client.h"
#include "tlv.h"
#include "util.h"

struct network_client_channel {
	struct channel *channel;
	struct network_client *nc;
	struct tlv_handler_ctx *tlv_ctx;
	uint32_t retries;
};

static void
network_client_channel_free(struct network_client_channel *nc)
{
	if (nc) {
		if (nc->nc) {
			network_client_free(nc->nc);
		}
		free(nc);
	}
}

void network_channel_read_cb(struct bufferev *be, void *arg)
{
	struct network_client_channel *ncc = arg;
	size_t len = bufferev_bytes_available(be);
	void *buf = malloc(len);
	if (buf) {
		bufferev_read(be, buf, len);
		channel_enqueue(ncc->channel, buf, len);
		free(buf);
	}
}

void network_channel_event_cb(struct bufferev *be, int event, void *arg)
{
	struct network_client_channel *ncc = arg;
	struct tlv_handler_ctx *tlv_ctx = ncc->tlv_ctx;
	ncc->tlv_ctx = NULL;

	if (tlv_ctx) {
		struct tlv_packet *p = NULL;

		if (event & BEV_CONNECTED) {
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_SUCCESS);
			channel_opened(ncc->channel);

		} else if (event & BEV_ERROR) {
			tlv_ctx->channel_id = 0;
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_FAILURE);
			channel_shutdown(ncc->channel);
			network_client_channel_free(ncc);
		}

		tlv_dispatcher_enqueue_response(tlv_ctx->td, p);
		tlv_handler_ctx_free(tlv_ctx);

	} else {
		if (event & (BEV_EOF | BEV_ERROR)) {
			channel_set_ctx(ncc->channel, NULL);
			channel_send_close_request(ncc->channel);
			network_client_channel_free(ncc);
		}
	}
}

static struct network_client_channel*
network_client_channel_alloc(struct tlv_handler_ctx *tlv_ctx, struct channel *c,
		struct ev_loop *loop, uint32_t retries,
		const char *proto, const char *dst_host, uint16_t dst_port)
{
	struct network_client_channel *ncc = calloc(1, sizeof(*ncc));
	if (ncc == NULL) {
		return NULL;
	}

	ncc->tlv_ctx = tlv_ctx;
	ncc->channel = c;

	ncc->nc = network_client_new(loop);
	if (ncc->nc == NULL) {
		network_client_channel_free(ncc);
		return NULL;
	}

	char *uri = NULL;
	if (asprintf(&uri, "%s://%s:%u", proto, dst_host, dst_port) == -1 ||
	        network_client_add_uri(ncc->nc, uri) == -1) {
		network_client_channel_free(ncc);
		return NULL;
	}
	free(uri);

	network_client_setcbs(ncc->nc, network_channel_read_cb, NULL,
			network_channel_event_cb, ncc);
	network_client_set_retries(ncc->nc, ncc->retries);
	network_client_start(ncc->nc);

	return ncc;
}

static int
_network_client_new(struct tlv_handler_ctx *ctx, struct channel *c, const char *proto)
{
	const char *src_host, *dst_host;
	uint32_t src_port = -1, dst_port = -1;
	struct mettle *m = ctx->arg;
	uint32_t retries = 0;

	dst_host = tlv_packet_get_str(ctx->req, TLV_TYPE_PEER_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_PEER_PORT, &dst_port);

	src_host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_HOST, &src_port);

	tlv_packet_get_u32(ctx->req, TLV_TYPE_CONNECT_RETRIES, &retries);

	if (dst_host == NULL || dst_port == -1) {
		log_debug("dst_host %s, dst_port %u", dst_host, dst_port);
		return -1;
	}

	if (src_host && src_port != -1) {
		log_debug("src_host %s, src_port %u", src_host, src_port);
	}

	struct network_client_channel *ncc =
		network_client_channel_alloc(ctx, c, mettle_get_loop(m),
				retries, proto, dst_host, dst_port);
	if (ncc == NULL) {
		goto err;
	}

	channel_set_ctx(c, ncc);
	channel_set_interactive(c, true);

	return 0;

err:
	network_client_channel_free(ncc);
	return -1;

}

static int tcp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	return _network_client_new(ctx, c, "tcp");
}

static ssize_t tcp_client_read(struct channel *c, void *buf, size_t len)
{
	struct network_client_channel *ncc = channel_get_ctx(c);
	return network_client_read(ncc->nc, buf, len);
}

static ssize_t tcp_client_write(struct channel *c, void *buf, size_t len)
{
	struct network_client_channel *ncc = channel_get_ctx(c);
	return network_client_write(ncc->nc, buf, len);
}

static int tcp_client_free(struct channel *c)
{
	struct network_client_channel *ncc = channel_get_ctx(c);
	if (ncc) {
		channel_set_ctx(c, NULL);
		network_client_channel_free(ncc);
	}
	return 0;
}

static struct tlv_packet *tcp_shutdown(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	uint32_t how = 0;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SHUTDOWN_HOW, &how);

	const char *reasons[] = {"reads", "writes", "reads and writes", "unknown reasons"};
	how = TYPESAFE_MIN(3, how);

	log_info("shutting down connection for %s", reasons[how]);

	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

static int udp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	return _network_client_new(ctx, c, "udp");
}

static ssize_t udp_client_read(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_read(nc, buf, len);
}

static ssize_t udp_client_write(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_write(nc, buf, len);
}

static int udp_client_free(struct channel *c)
{
	struct network_client *nc = channel_get_ctx(c);
	network_client_free(nc);
	return 0;
}

void net_client_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	struct channel_callbacks tcp_client_cbs = {
		.new_async_cb = tcp_client_new,
		.read_cb = tcp_client_read,
		.write_cb = tcp_client_write,
		.free_cb = tcp_client_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_net_tcp_client", &tcp_client_cbs);
	tlv_dispatcher_add_handler(td, "stdapi_net_socket_tcp_shutdown", tcp_shutdown, m);

	struct channel_callbacks udp_client_cbs = {
		.new_cb = udp_client_new,
		.read_cb = udp_client_read,
		.write_cb = udp_client_write,
		.free_cb = udp_client_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_net_udp_client", &udp_client_cbs);
}

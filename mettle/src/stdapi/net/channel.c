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

/*
 * Handlers registered with the network client to send data to the channel manager
 */
static void network_channel_close_cb(struct network_client *nc, void *arg)
{
	struct channel *c = arg;
	channel_set_ctx(c, NULL);
}

static void network_channel_read_cb(struct network_client *nc, void *arg)
{
	struct channel *c = arg;
	size_t len = network_client_bytes_available(nc);
	void *buf = malloc(len);
	log_debug("got %zu bytes", len);
	if (buf) {
		network_client_read(nc, buf, len);
		channel_enqueue(c, buf, len);
		free(buf);
	}
}

static int _network_client_new(struct tlv_handler_ctx *ctx, struct channel *c, const char *proto)
{
	const char *src_host, *dst_host;
	uint32_t src_port = -1, dst_port = -1;
	struct mettle *m = ctx->arg;
	struct network_client *nc = NULL;

	dst_host = tlv_packet_get_str(ctx->req, TLV_TYPE_PEER_HOST);
	src_host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);

	tlv_packet_get_u32(ctx->req, TLV_TYPE_PEER_PORT, &dst_port);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_HOST, &src_port);

	if (dst_host == NULL || dst_port == -1) {
		log_debug("dst_host %s, dst_port %u", dst_host, dst_port);
		goto err;
	}

	if (src_host && src_port) {
		log_debug("src_host %s, src_port %u", src_host, src_port);
	}

	nc = network_client_new(mettle_get_loop(m));
	if (nc == NULL) {
		log_debug("could not allocate network client");
		goto err;
	}

	char *uri = NULL;
	if (asprintf(&uri, "%s://%s:%u", proto, dst_host, dst_port) == -1) {
		goto err;
	}

	if (network_client_add_server(nc, uri) == -1) {
		log_debug("could not add server for uri %s", uri);
		goto err;
	}

	free(uri);

	channel_set_ctx(c, nc);
	channel_set_interactive(c, true);
	network_client_set_read_cb(nc, network_channel_read_cb, c);
	network_client_set_close_cb(nc, network_channel_close_cb, c);
	network_client_start(nc);

	return 0;

err:
	if (nc) {
		network_client_free(nc);
	}
	return -1;

}

static int tcp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	return _network_client_new(ctx, c, "tcp");
}

ssize_t tcp_client_read(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_read(nc, buf, len);
}

ssize_t tcp_client_write(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_write(nc, buf, len);
}

int tcp_client_free(struct channel *c)
{
	struct network_client *nc = channel_get_ctx(c);
	if (nc) {
		network_client_free(nc);
		channel_set_ctx(c, NULL);
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

	/*
	tcp_client_free(c);
	channel_free(c);
	*/

	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

static int udp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	return _network_client_new(ctx, c, "udp");
}

ssize_t udp_client_read(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_read(nc, buf, len);
}

ssize_t udp_client_write(struct channel *c, void *buf, size_t len)
{
	struct network_client *nc = channel_get_ctx(c);
	return network_client_write(nc, buf, len);
}

int udp_client_free(struct channel *c)
{
	struct network_client *nc = channel_get_ctx(c);
	network_client_free(nc);
	return 0;
}

void net_channel_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	struct channel_callbacks tcp_client_cbs = {
		.new_cb = tcp_client_new,
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

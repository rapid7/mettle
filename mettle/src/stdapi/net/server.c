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
#include "command_ids.h"
#include "utils.h"

struct network_server_channel
{
	struct tlv_dispatcher *td;
	struct channel *channel;
	struct network_server *ns;
};

struct tcp_server_conn
{
	struct channel *channel;
	struct bufferev *be;
};

static void conn_read_cb(struct bufferev *be, void *arg)
{
	struct tcp_server_conn *conn = arg;
	channel_enqueue_buffer_queue(conn->channel, bufferev_rx_queue(be));
}

static void conn_event_cb(struct bufferev *be, int event, void *arg)
{
	struct tcp_server_conn *conn = arg;

	if (event & (BEV_EOF | BEV_ERROR)) {
		channel_set_ctx(conn->channel, NULL);
		channel_send_close_request(conn->channel);
		free(conn);
	}
}

static void open_tcp_channel(struct network_server_channel *nsc, struct bufferev *be)
{
	struct channelmgr *cm = channel_get_channelmgr(nsc->channel);
	struct tcp_server_conn *conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		return;
	}

	conn->be = be;
	conn->channel = channelmgr_channel_new(cm, "tcp_server_conn");
	if (conn->channel == NULL) {
		return;
	}

	struct tlv_packet *p = tlv_packet_new(TLV_PACKET_TYPE_REQUEST, 128);
	if (p == NULL) {
		channel_free(conn->channel);
		return;
	}

	p = tlv_packet_add_uuid(p, nsc->td);
	p = tlv_packet_add_u32(p, TLV_TYPE_COMMAND_ID, COMMAND_ID_STDAPI_NET_TCP_CHANNEL_OPEN);
	p = tlv_packet_add_fmt(p, TLV_TYPE_REQUEST_ID,
			"channel-req-%d", channel_get_id(conn->channel));
	p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_get_id(conn->channel));
	p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_PARENTID, channel_get_id(nsc->channel));

	uint16_t local_port;
	char *local_host = bufferev_get_local_addr(be, &local_port);
	if (local_host) {
		p = tlv_packet_add_str(p, TLV_TYPE_LOCAL_HOST, local_host);
		p = tlv_packet_add_u32(p, TLV_TYPE_LOCAL_PORT, local_port);
		free(local_host);
		local_host = NULL;
	}

	uint16_t peer_port;
	char *peer_host = bufferev_get_peer_addr(be, &peer_port);
	if (peer_host) {
		p = tlv_packet_add_str(p, TLV_TYPE_PEER_HOST, peer_host);
		p = tlv_packet_add_u32(p, TLV_TYPE_PEER_PORT, peer_port);
		free(peer_host);
		peer_host = NULL;
	}

	bufferev_set_cbs(be, conn_read_cb, NULL, conn_event_cb, conn);
	channel_set_ctx(conn->channel, conn);
	channel_set_interactive(conn->channel, true);

	tlv_dispatcher_enqueue_response(nsc->td, p);
}

static void tcp_server_event_cb(struct bufferev *be, int event, void *arg)
{
	struct network_server_channel *nsc = arg;

	if (event & BEV_CONNECTED) {
		open_tcp_channel(nsc, be);
	}
}

static int tcp_server_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	uint32_t port = 0;
	struct mettle *m = ctx->arg;
	struct network_server_channel *nsc;
	struct tlv_packet *p = NULL;
	char *host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);

	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_PORT, &port) == -1) {
		log_error("no port specified");
		return -1;
	}

	nsc = calloc(1, sizeof(*nsc));
	if (nsc == NULL) {
		return -1;
	}

	nsc->channel = c;
	nsc->td = mettle_get_tlv_dispatcher(m);

	nsc->ns = network_server_new(mettle_get_loop(m));
	if (network_server_listen_tcp(nsc->ns, host, port) == -1) {
		log_info("failed to listen on %s:%d", host, port);
		network_server_free(nsc->ns);
		free(nsc);
		return -1;
	}

	network_server_setcbs(nsc->ns, NULL, NULL, tcp_server_event_cb, nsc);
	channel_set_ctx(c, nsc);
	log_info("listening on %s:%d", host, port);

	p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	host = network_server_get_local_addr(nsc->ns, (uint16_t*)&port);
	if (host) {
		p = tlv_packet_add_str(p, TLV_TYPE_LOCAL_HOST, host);
		p = tlv_packet_add_u32(p, TLV_TYPE_LOCAL_PORT, port);
		free(host);
		host = NULL;
	}
	tlv_dispatcher_enqueue_response(ctx->td, p);
	return 0;
}

static int tcp_server_free(struct channel *c)
{
	struct network_server_channel *nsc = channel_get_ctx(c);
	if (nsc) {
		channel_set_ctx(c, NULL);
		if (nsc->ns) {
			network_server_free(nsc->ns);
			nsc->ns = NULL;
		}
		free(nsc);
	}
	return 0;
}

static ssize_t tcp_conn_read(struct channel *c, void *buf, size_t len)
{
	struct tcp_server_conn *conn = channel_get_ctx(c);
	if (conn == NULL) {
		errno = EIO;
		return -1;
	}
	return bufferev_read(conn->be, buf, len);
}

static ssize_t tcp_conn_write(struct channel *c, void *buf, size_t len)
{
	struct tcp_server_conn *conn = channel_get_ctx(c);
	if (conn == NULL) {
		errno = EIO;
		return -1;
	}
	return bufferev_write(conn->be, buf, len);
}

static int tcp_conn_free(struct channel *c)
{
	struct tcp_server_conn *conn = channel_get_ctx(c);
	if (conn) {
		channel_set_ctx(c, NULL);
		bufferev_free(conn->be);
		free(conn);
	}
	return 0;
}

void net_server_register_handlers(struct mettle *m)
{
	struct channelmgr *cm = mettle_get_channelmgr(m);

	struct channel_callbacks tcp_server_cbs = {
		.new_async_cb = tcp_server_new,
		.free_cb = tcp_server_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_net_tcp_server", &tcp_server_cbs);

	struct channel_callbacks tcp_conn_cbs = {
		.read_cb = tcp_conn_read,
		.write_cb = tcp_conn_write,
		.free_cb = tcp_conn_free,
	};
	channelmgr_add_channel_type(cm, "tcp_server_conn", &tcp_conn_cbs);

}


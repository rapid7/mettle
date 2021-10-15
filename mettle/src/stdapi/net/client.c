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
#include "command_ids.h"
#include "utils.h"

struct tcp_client_channel {
	struct channel *channel;
	struct network_client *nc;
	struct tlv_handler_ctx *tlv_ctx;
	uint32_t retries;
};

static void
tcp_client_channel_free(struct tcp_client_channel *tcc)
{
	if (tcc) {
		log_debug("closing tcp client channel: %p", tcc);
		if (tcc->nc) {
			network_client_free(tcc->nc);
		}
		free(tcc);
	}
}

static void
tcp_client_channel_read_cb(struct bufferev *be, void *arg)
{
	struct tcp_client_channel *tcc = arg;
	channel_enqueue_buffer_queue(tcc->channel, bufferev_rx_queue(be));
}

static void
tcp_client_channel_event_cb(struct bufferev *be, int event, void *arg)
{
	struct tcp_client_channel *tcc = arg;
	struct tlv_handler_ctx *tlv_ctx = tcc->tlv_ctx;
	tcc->tlv_ctx = NULL;

	if (tlv_ctx) {
		struct tlv_packet *p = NULL;

		if (event & BEV_CONNECTED) {
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_SUCCESS);
			uint16_t local_port;
			char *local_host = bufferev_get_local_addr(be, &local_port);
			if (local_host) {
				p = tlv_packet_add_str(p, TLV_TYPE_LOCAL_HOST, local_host);
				p = tlv_packet_add_u32(p, TLV_TYPE_LOCAL_PORT, local_port);
				free(local_host);
				local_host = NULL;
			}
			channel_opened(tcc->channel);

		} else if (event & BEV_ERROR) {
			tlv_ctx->channel_id = 0;
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_FAILURE);
			channel_shutdown(tcc->channel);
			tcp_client_channel_free(tcc);
		}

		tlv_dispatcher_enqueue_response(tlv_ctx->td, p);
		tlv_handler_ctx_free(tlv_ctx);

	} else {
		if (event & (BEV_EOF | BEV_ERROR)) {
			channel_set_ctx(tcc->channel, NULL);
			channel_send_close_request(tcc->channel);
			tcp_client_channel_free(tcc);
		}
	}
}

static bool
host_is_ipv6_address(const char *dst_host) {
	bool is_ipv6 = false;
	struct addrinfo *resolved_host = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_flags = AI_NUMERICHOST,
	};
	
	if (getaddrinfo(dst_host, NULL, &hints, &resolved_host) == 0) {
		is_ipv6 = resolved_host->ai_family == AF_INET6;
		freeaddrinfo(resolved_host);
	}
	return is_ipv6;
}

static int
tcp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	const char *src_host, *dst_host, *uri_fmt;
	uint32_t src_port = 0, dst_port = 0;
	struct mettle *m = ctx->arg;
	uint32_t retries = 0;
	char *uri = NULL;

	dst_host = tlv_packet_get_str(ctx->req, TLV_TYPE_PEER_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_PEER_PORT, &dst_port);

	src_host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_PORT, &src_port);

	tlv_packet_get_u32(ctx->req, TLV_TYPE_CONNECT_RETRIES, &retries);

	struct tcp_client_channel *tcc = calloc(1, sizeof(*tcc));
	if (tcc == NULL) {
		goto err;
	}

	tcc->tlv_ctx = ctx;
	tcc->channel = c;

	tcc->nc = network_client_new(mettle_get_loop(m));
	if (tcc->nc == NULL) {
		goto err;
	}

	uri_fmt = host_is_ipv6_address(dst_host) ? "tcp://[%s]:%u" : "tcp://%s:%u";
	if (asprintf(&uri, uri_fmt, dst_host, dst_port) == -1 ||
			network_client_add_uri(tcc->nc, uri) == -1) {
		goto err;
	}

	network_client_set_cbs(tcc->nc,
			tcp_client_channel_read_cb, NULL,
			tcp_client_channel_event_cb, tcc);
	if (src_host || src_port) {
		network_client_set_src(tcc->nc, src_host, src_port);
	}
	network_client_set_retries(tcc->nc, tcc->retries);
	network_client_start(tcc->nc);

	channel_set_ctx(c, tcc);
	channel_set_interactive(c, true);
	free(uri);

	return 0;

err:
	free(uri);
	tcp_client_channel_free(tcc);
	return -1;
}

static ssize_t
tcp_client_read(struct channel *c, void *buf, size_t len)
{
	struct tcp_client_channel *tcc = channel_get_ctx(c);
	if (tcc == NULL) {
		errno = EIO;
		return -1;
	}
	return network_client_read(tcc->nc, buf, len);
}

static ssize_t
tcp_client_write(struct channel *c, void *buf, size_t len)
{
	struct tcp_client_channel *tcc = channel_get_ctx(c);
	if (tcc == NULL) {
		errno = EIO;
		return -1;
	}
	return network_client_write(tcc->nc, buf, len);
}

static int
tcp_client_free(struct channel *c)
{
	struct tcp_client_channel *tcc = channel_get_ctx(c);
	if (tcc) {
		channel_set_ctx(c, NULL);
		tcp_client_channel_free(tcc);
	}
	return 0;
}

static struct tlv_packet *
tcp_shutdown(struct tlv_handler_ctx *ctx)
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

struct udp_client_channel {
	struct channel *channel;
	struct network_client *nc;
	struct tlv_handler_ctx *tlv_ctx;
};

static void
udp_client_channel_free(struct udp_client_channel *ucc)
{
	if (ucc) {
		log_debug("closing udp client channel: %p", ucc);
		if (ucc->nc) {
			network_client_free(ucc->nc);
		}
		free(ucc);
	}
}

static void
udp_client_channel_read_cb(struct bufferev *be, void *arg)
{
	struct udp_client_channel *ucc = arg;
	size_t len;
	struct bufferev_udp_msg *msg;
	while ((msg = bufferev_read_msg(be, &len))) {
		uint16_t peer_port = 0;
		char * peer_host = bufferev_get_udp_msg_peer_addr(msg, &peer_port);

		if (peer_host) {
			struct tlv_packet *p = tlv_packet_new(0, 32);
			p = tlv_packet_add_str(p, TLV_TYPE_PEER_HOST, peer_host);
			p = tlv_packet_add_u32(p, TLV_TYPE_PEER_PORT, peer_port);
			channel_enqueue_ex(ucc->channel, msg->buf, msg->buf_len, p);
		}
		free(peer_host);
	}
}

static void
udp_client_channel_event_cb(struct bufferev *be, int event, void *arg)
{
	struct udp_client_channel *tcc = arg;
	struct tlv_handler_ctx *tlv_ctx = tcc->tlv_ctx;
	tcc->tlv_ctx = NULL;

	if (tlv_ctx) {
		struct tlv_packet *p = NULL;

		if (event & BEV_CONNECTED) {
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_SUCCESS);
			uint16_t local_port;
			char *local_host = bufferev_get_local_addr(be, &local_port);
			if (local_host) {
				p = tlv_packet_add_str(p, TLV_TYPE_LOCAL_HOST, local_host);
				p = tlv_packet_add_u32(p, TLV_TYPE_LOCAL_PORT, local_port);
				free(local_host);
				local_host = NULL;
			}
			channel_opened(tcc->channel);

		} else if (event & BEV_ERROR) {
			tlv_ctx->channel_id = 0;
			p = tlv_packet_response_result(tlv_ctx, TLV_RESULT_FAILURE);
			channel_shutdown(tcc->channel);
			udp_client_channel_free(tcc);
		}

		tlv_dispatcher_enqueue_response(tlv_ctx->td, p);
		tlv_handler_ctx_free(tlv_ctx);

	} else {
		if (event & (BEV_EOF | BEV_ERROR)) {
			channel_set_ctx(tcc->channel, NULL);
			channel_send_close_request(tcc->channel);
			udp_client_channel_free(tcc);
		}
	}
}

static int
udp_client_new(struct tlv_handler_ctx *ctx, struct channel *c)
{
	const char *src_host, *dst_host, *uri_fmt;
	uint32_t src_port = 0, dst_port = 0;
	struct mettle *m = ctx->arg;
	char *uri = NULL;

	dst_host = tlv_packet_get_str(ctx->req, TLV_TYPE_PEER_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_PEER_PORT, &dst_port);

	src_host = tlv_packet_get_str(ctx->req, TLV_TYPE_LOCAL_HOST);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_LOCAL_HOST, &src_port);

	struct udp_client_channel *uc = calloc(1, sizeof(*uc));
	if (uc == NULL) {
		goto err;
	}

	uc->tlv_ctx = ctx;
	uc->channel = c;

	uc->nc = network_client_new(mettle_get_loop(m));
	if (uc->nc == NULL) {
		goto err;
	}

	uri_fmt = host_is_ipv6_address(dst_host) ? "udp://[%s]:%u" : "udp://%s:%u";
	if (asprintf(&uri, uri_fmt, dst_host, dst_port) == -1 ||
			network_client_add_uri(uc->nc, uri) == -1) {
		goto err;
	}

	network_client_set_cbs(uc->nc,
			udp_client_channel_read_cb, NULL,
			udp_client_channel_event_cb, uc);
	if (src_host || src_port) {
		network_client_set_src(uc->nc, src_host, src_port);
	}
	network_client_set_retries(uc->nc, 0);
	network_client_start(uc->nc);

	channel_set_ctx(c, uc);
	channel_set_interactive(c, true);
	free(uri);

	return 0;

err:
	free(uri);
	udp_client_channel_free(uc);
	return -1;
	return 0;
}

static ssize_t
udp_client_read(struct channel *c, void *buf, size_t len)
{
	size_t msg_len;
	struct udp_client_channel *ucc = channel_get_ctx(c);
	if (ucc == NULL) {
		errno = EIO;
		return -1;
	}
	void *msg_buf = network_client_read_msg(ucc->nc, &msg_len);
	if (msg_buf == NULL) {
		errno = EIO;
		return -1;
	}
	memcpy(buf, msg_buf, TYPESAFE_MIN(len, msg_len));
	return msg_len;
}

static ssize_t
udp_client_write(struct channel *c, void *buf, size_t len)
{
	struct udp_client_channel *ucc = channel_get_ctx(c);
	if (ucc == NULL) {
		errno = EIO;
		return -1;
	}
	return network_client_write(ucc->nc, buf,
			TYPESAFE_MIN(len, IP_LEN_MAX - IP_HDR_LEN - UDP_HDR_LEN));
}

static int
udp_client_free(struct channel *c)
{
	struct udp_client_channel *ucc = channel_get_ctx(c);
	if (ucc) {
		channel_set_ctx(c, NULL);
		udp_client_channel_free(ucc);
	}
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
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_SOCKET_TCP_SHUTDOWN, tcp_shutdown, m);

	struct channel_callbacks udp_client_cbs = {
		.new_async_cb = udp_client_new,
		.read_cb = udp_client_read,
		.write_cb = udp_client_write,
		.free_cb = udp_client_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_net_udp_client", &udp_client_cbs);
}

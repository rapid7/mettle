
/**
 * @brief c2_tcp.c TCP transport
 * @file c2_tcp.c
 */

#include <stdlib.h>

#include "c2.h"
#include "log.h"
#include "network_client.h"
#include "tlv.h"

struct tcp_ctx {
	struct network_client *nc;
	int first_packet;
};

static void tcp_read_cb(struct bufferev *be, void *arg)
{
	struct c2_transport *t = arg;
	struct tcp_ctx *ctx = c2_transport_get_ctx(t);
	if (ctx->first_packet) {
		struct buffer_queue *q = bufferev_rx_queue(be);
		if (tlv_found_first_packet(q)) {
			ctx->first_packet = 0;
		} else {
			return;
		}
	}
	c2_transport_ingress_queue(t, bufferev_read_queue(be));
}

static void tcp_event_cb(struct bufferev *be, int event, void *arg)
{
	struct c2_transport *t = arg;
	if (event & BEV_CONNECTED) {
		struct tcp_ctx *ctx = c2_transport_get_ctx(t);
		if (ctx) {
			ctx->first_packet = 1;
		}
		c2_transport_reachable(t);
	} else {
		c2_transport_unreachable(t);
	}
}

int fd_transport_init(struct c2_transport *t)
{
	int fd = strtol(c2_transport_dest(t), NULL, 10);
	if (fd < 0) {
		return -1;
	}

	struct tcp_ctx *ctx = calloc(1, sizeof *ctx);
	if (ctx == NULL) {
		return -1;
	}

	ctx->nc = network_client_new(c2_transport_loop(t));
	if (ctx->nc == NULL) {
		free(ctx);
		return -1;
	}

	network_client_add_tcp_sock(ctx->nc, fd);
	network_client_set_retries(ctx->nc, 0);
	network_client_set_cbs(ctx->nc, tcp_read_cb, NULL, tcp_event_cb, t);
	ctx->first_packet = 1;
	c2_transport_set_ctx(t, ctx);
	return 0;
}

int tcp_transport_init(struct c2_transport *t)
{
	struct tcp_ctx *ctx = calloc(1, sizeof *ctx);
	if (ctx == NULL) {
		return -1;
	}

	ctx->nc = network_client_new(c2_transport_loop(t));
	if (ctx->nc == NULL) {
		free(ctx);
		return -1;
	}

	network_client_add_uri(ctx->nc, c2_transport_uri(t));
	network_client_set_retries(ctx->nc, 0);
	network_client_set_cbs(ctx->nc, tcp_read_cb, NULL, tcp_event_cb, t);
	ctx->first_packet = 1;
	c2_transport_set_ctx(t, ctx);
	return 0;
}

void tcp_transport_start(struct c2_transport *t)
{
	struct tcp_ctx *ctx = c2_transport_get_ctx(t);
	network_client_start(ctx->nc);
}

void tcp_transport_egress(struct c2_transport *t, struct buffer_queue *egress)
{
	struct tcp_ctx *ctx = c2_transport_get_ctx(t);
	void *buf = NULL;
	size_t buflen = buffer_queue_remove_all(egress, &buf);
	if (buf) {
		network_client_write(ctx->nc, buf, buflen);
		free(buf);
	}
}

void tcp_transport_stop(struct c2_transport *t)
{
	struct tcp_ctx *ctx = c2_transport_get_ctx(t);
	network_client_stop(ctx->nc);
}

void tcp_transport_free(struct c2_transport *t)
{
	struct tcp_ctx *ctx = c2_transport_get_ctx(t);
	network_client_free(ctx->nc);
	free(ctx);
	c2_transport_set_ctx(t, NULL);
}

void c2_register_tcp_transports(struct c2 *c2)
{
	struct c2_transport_cbs tcp_cbs = {
		.init = tcp_transport_init,
		.start = tcp_transport_start,
		.egress = tcp_transport_egress,
		.stop = tcp_transport_stop,
		.free = tcp_transport_free
	};

	c2_register_transport_type(c2, "tcp", &tcp_cbs);

	tcp_cbs.init = fd_transport_init;

	c2_register_transport_type(c2, "fd", &tcp_cbs);
}

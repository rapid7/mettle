
/**
 * @brief c2_tcp.c TCP transport
 * @file c2_tcp.c
 */

#include <stdlib.h>

#include "c2.h"
#include "network_client.h"
#include "log.h"

static void tcp_read_cb(struct bufferev *be, void *arg)
{
	struct c2_transport *t = arg;
	c2_transport_ingress_queue(t, bufferev_read_queue(be));
}

static void tcp_event_cb(struct bufferev *be, int event, void *arg)
{
	struct c2_transport *t = arg;
	if (event & BEV_CONNECTED) {
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
	struct network_client *nc = network_client_new(c2_transport_loop(t));
	if (nc == NULL) {
		return -1;
	}
	network_client_add_tcp_sock(nc, fd);
	network_client_set_retries(nc, 0);
	network_client_set_cbs(nc, tcp_read_cb, NULL, tcp_event_cb, t);
	c2_transport_set_ctx(t, nc);
	return 0;
}

int tcp_transport_init(struct c2_transport *t)
{
	struct network_client *nc = network_client_new(c2_transport_loop(t));
	if (nc == NULL) {
		return -1;
	}
	network_client_add_uri(nc, c2_transport_uri(t));
	network_client_set_retries(nc, 0);
	network_client_set_cbs(nc, tcp_read_cb, NULL, tcp_event_cb, t);
	c2_transport_set_ctx(t, nc);
	return 0;
}

void tcp_transport_start(struct c2_transport *t)
{
	struct network_client *nc = c2_transport_get_ctx(t);
	network_client_start(nc);
}

void tcp_transport_egress(struct c2_transport *t, struct buffer_queue *egress)
{
	struct network_client *nc = c2_transport_get_ctx(t);
	void *buf = NULL;
	size_t buflen = buffer_queue_remove_all(egress, &buf);
	if (buf) {
		network_client_write(nc, buf, buflen);
		free(buf);
	}
}

void tcp_transport_stop(struct c2_transport *t)
{
	struct network_client *nc = c2_transport_get_ctx(t);
	network_client_stop(nc);
}

void tcp_transport_free(struct c2_transport *t)
{
	struct network_client *nc = c2_transport_get_ctx(t);
	network_client_free(nc);
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

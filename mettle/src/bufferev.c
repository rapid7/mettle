/**
 * Copyright 2015 Rapid7
 * @brief Durable multi-transport client network connection
 * @file network-client.h
 */

#include <ev.h>
#include <eio.h>
#include <errno.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "buffer_queue.h"
#include "log.h"
#include "bufferev.h"
#include "utils.h"

struct bufferev {
	struct ev_timer connect_timer;
	struct ev_loop *loop;

	char *uri;
	enum network_proto proto;
	int sock, connected;
	struct ev_io data_ev;

	struct buffer_queue *tx_queue;
	struct buffer_queue *rx_queue;

	bufferev_data_cb read_cb;
	bufferev_data_cb write_cb;
	bufferev_event_cb event_cb;
	void *cb_arg;

	char *host;
	char **services;
	int num_services;
};

void bufferev_set_cbs(struct bufferev *be,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg)
{
	be->read_cb = read_cb;
	be->write_cb = write_cb;
	be->event_cb = event_cb;
	be->cb_arg = cb_arg;
}

struct buffer_queue * bufferev_rx_queue(struct bufferev *be)
{
	return be->rx_queue;
}

size_t bufferev_bytes_available(struct bufferev *be)
{
	return buffer_queue_len(be->rx_queue);
}

size_t bufferev_peek(struct bufferev *be, void *buf, size_t buflen)
{
	return buffer_queue_copy(be->rx_queue, buf, buflen);
}

size_t bufferev_read(struct bufferev *be, void *buf, size_t buflen)
{
	return buffer_queue_remove(be->rx_queue, buf, buflen);
}

struct buffer_queue *bufferev_read_queue(struct bufferev *be)
{
	return be->rx_queue;
}

void *bufferev_read_msg(struct bufferev *be, size_t *len)
{
	return buffer_queue_remove_msg(be->rx_queue, len);
}

void *bufferev_peek_msg(struct bufferev *be, size_t *len)
{
	return buffer_queue_peek_msg(be->rx_queue, len);
}

ssize_t bufferev_write(struct bufferev *be, const void *buf, size_t buflen)
{
	ssize_t off = 0, rc;
	ssize_t sent_bytes = 0;

	switch (be->proto) {
	case network_proto_udp:
		return send(be->sock, buf, buflen, 0);
	case network_proto_tcp:
		do {
			rc = send(be->sock, buf + off, buflen - off, 0);
			if (rc > 0) {
				off += rc;
				sent_bytes += rc;
			}
		} while (rc > 0 || (rc < 0 && (errno == EAGAIN || errno == EINTR)));
		return sent_bytes ? sent_bytes : rc;

	case network_proto_tls:
		return buffer_queue_add(be->tx_queue, buf, buflen);
	}

	return -1;
}

static void on_read_tcp(struct bufferev *be)
{
	size_t bytes_read = 0;
	char buf[65535];
	ssize_t rc;
	while ((rc = read(be->sock, buf, sizeof(buf))) > 0) {
		bytes_read += rc;
		buffer_queue_add(be->rx_queue, buf, rc);
	}
	int my_errno = errno;

	if (bytes_read > 0) {
		if (be->read_cb) {
			be->read_cb(be, be->cb_arg);
		}
	}

	/*
	 * The socket shutdown as expected
	 */
	if (rc == 0) {
		ev_io_stop(be->loop, &be->data_ev);
		if (be->event_cb) {
			be->event_cb(be, BEV_EOF, be->cb_arg);
		}
	} else if (rc == -1 && my_errno != EAGAIN && my_errno != EINPROGRESS && my_errno != EWOULDBLOCK) {
		/*
		 * An error occurred
		 */
		ev_io_stop(be->loop, &be->data_ev);
		if (be->event_cb) {
			be->event_cb(be, BEV_EOF | BEV_ERROR, be->cb_arg);
		}
	}
}

static void on_read_udp(struct bufferev *be)
{
	size_t bytes_read = 0;
	struct bufferev_udp_msg *msg = calloc(1, sizeof(*msg) + 65535);

	do {
		msg->src_len = sizeof(msg->src),
		msg->buf_len = recvfrom(be->sock, msg->buf, 65535, 0,
					(struct sockaddr *)&msg->src, &msg->src_len);
		if (msg->buf_len > 0) {
			bytes_read += msg->buf_len;
			buffer_queue_add(be->rx_queue, msg, sizeof(*msg) + msg->buf_len);
		}
	} while (msg->buf_len > 0);

	if (bytes_read > 0) {
		if (be->read_cb) {
			be->read_cb(be, be->cb_arg);
		}
	}
}

static void
on_read(struct ev_loop *loop, struct ev_io *w, int events)
{
	struct bufferev *be = w->data;

	switch (be->proto) {
	case network_proto_tcp:
		on_read_tcp(be);
		break;
	case network_proto_udp:
		on_read_udp(be);
		break;
	case network_proto_tls:
		break;
	}
}

static void
close_sock(struct bufferev *be)
{
	if (be->sock >= 0) {
		close(be->sock);
		be->sock = -1;
	}
}

static void
on_connect_timeout(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct bufferev *be = (struct bufferev *)w;

	ev_timer_stop(be->loop, &be->connect_timer);

	if (!be->connected) {
		close_sock(be);
		ev_io_stop(be->loop, &be->data_ev);

		if (be->event_cb) {
			be->event_cb(be, BEV_ERROR | BEV_TIMEOUT, be->cb_arg);
		}
	}
}

static void
on_connect(struct ev_loop *loop, struct ev_io *w, int events)
{
	struct bufferev *be = w->data;

	ev_io_stop(be->loop, &be->data_ev);
	ev_timer_stop(be->loop, &be->connect_timer);

	int status;
	socklen_t len = sizeof(status);
	getsockopt(be->sock, SOL_SOCKET, SO_ERROR, &status, &len);
	if (status != 0) {
		if (be->event_cb) {
			be->event_cb(be, BEV_ERROR, be->cb_arg);
		}
		return;
	}

	if (be->event_cb) {
		be->event_cb(be, BEV_CONNECTED, be->cb_arg);
	}

	ev_io_init(&be->data_ev, on_read, be->sock, EV_READ);
	be->data_ev.data = be;
	ev_io_start(be->loop, &be->data_ev);
	be->connected = 1;
}

int bufferev_connect_addrinfo(struct bufferev *be,
	struct addrinfo *src, struct addrinfo *dst, float timeout_s)
{
	be->sock = socket(dst->ai_family, dst->ai_socktype, dst->ai_protocol);
	if (be->sock < 0) {
		return -1;
	}

	make_socket_nonblocking(be->sock);

	if (dst->ai_protocol == IPPROTO_UDP) {
		be->proto = network_proto_udp;

		struct sockaddr *udp_src;
		socklen_t udp_src_len;
		struct sockaddr_in any_src = {
			.sin_family = AF_INET,
			.sin_port = htons(0),
			.sin_addr.s_addr = INADDR_ANY
		};

		if (src) {
			udp_src = src->ai_addr;
			udp_src_len = src->ai_addrlen;
		} else {
			udp_src = (struct sockaddr *)(&any_src);
			udp_src_len = sizeof any_src;
		}

		if (bind(be->sock, udp_src, udp_src_len) != 0) {
			log_debug("could not bind: %s", strerror(errno));
		}

	} else {
		be->proto = network_proto_tcp;
		if (src) {
			if (bind(be->sock, src->ai_addr, src->ai_addrlen) != 0) {
				log_debug("could not bind: %s", strerror(errno));
			}
		}
	}

	int rc = connect(be->sock, dst->ai_addr, dst->ai_addrlen);
	if (rc == 0 || errno == EINPROGRESS || errno == EWOULDBLOCK) {
		ev_io_init(&be->data_ev, on_connect, be->sock, EV_WRITE);
		be->data_ev.data = be;
		ev_io_start(be->loop, &be->data_ev);

		ev_timer_init(&be->connect_timer, on_connect_timeout, timeout_s, 0);
		ev_timer_start(be->loop, &be->connect_timer);
	} else {
		close_sock(be);
		return -1;
	}
	return 0;
}

int bufferev_connect_tcp_sock(struct bufferev *be, int sock)
{
	be->sock = sock;

	make_socket_nonblocking(be->sock);

	be->proto = network_proto_tcp;

	ev_io_init(&be->data_ev, on_read, be->sock, EV_READ);
	be->data_ev.data = be;
	ev_io_start(be->loop, &be->data_ev);

	if (be->event_cb) {
		be->event_cb(be, BEV_CONNECTED, be->cb_arg);
	}

	return 0;
}

char * bufferev_get_udp_msg_peer_addr(struct bufferev_udp_msg *msg, uint16_t *port)
{
	return parse_sockaddr(&msg->src, port);
}

char * bufferev_get_local_addr(struct bufferev *be, uint16_t *port)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	if (getsockname(be->sock, (struct sockaddr *)&addr, &len) == -1) {
		return NULL;
	}

	return parse_sockaddr(&addr, port);
}

char * bufferev_get_peer_addr(struct bufferev *be, uint16_t *port)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	if (getpeername(be->sock, (struct sockaddr *)&addr, &len) == -1) {
		return NULL;
	}

	return parse_sockaddr(&addr, port);
}

void bufferev_free(struct bufferev *be)
{
	if (be) {
		ev_io_stop(be->loop, &be->data_ev);
		buffer_queue_free(be->rx_queue);
		buffer_queue_free(be->tx_queue);
		close_sock(be);
		free(be);
	}
}

struct bufferev * bufferev_new(struct ev_loop *loop)
{
	struct bufferev *be = calloc(1, sizeof(*be));
	if (!be) {
		return NULL;
	}

	be->rx_queue = buffer_queue_new();
	if (be->rx_queue == NULL) {
		goto err;
	}

	be->tx_queue = buffer_queue_new();
	if (be->tx_queue == NULL) {
		goto err;
	}

	be->loop = loop;

	return be;

err:
	bufferev_free(be);
	return NULL;
}

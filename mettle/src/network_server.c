/**
 * Copyright 2016 Rapid7
 * @file network_server.h
 */

#include <stdlib.h>
#include <unistd.h>

#include <ev.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <errno.h>
#include "bufferev.h"
#include "log.h"
#include "network_server.h"
#include "util.h"

struct network_server {
	struct ev_loop *loop;
	int listener;
	struct ev_io connect_event;
	struct sockaddr_in6 sin;

	char *host;
	uint16_t port;

	bufferev_data_cb read_cb;
	bufferev_data_cb write_cb;
	bufferev_event_cb event_cb;
	void *cb_arg;
};

void connect_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct network_server *ns = w->data;
	struct sockaddr_storage sockaddr;
	socklen_t slen;
	int fd = accept(ns->listener, (struct sockaddr *)&sockaddr, &slen);
	if (fd < 0) {
		log_error("could not accept: %s", strerror(errno));
	} else if (fd > FD_SETSIZE) {
		close(fd);
	} else {
		make_socket_nonblocking(fd);
		struct bufferev *be = bufferev_new(loop);
		if (be) {
			bufferev_set_cbs(be, ns->read_cb, ns->write_cb, ns->event_cb, ns->cb_arg);
			bufferev_connect_tcp_sock(be, fd);
		}
	}
}

void network_server_setcbs(struct network_server *ns,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg)
{
    ns->read_cb = read_cb;
    ns->write_cb = write_cb;
    ns->event_cb = event_cb;
    ns->cb_arg = cb_arg;
}

struct network_server * network_server_new(struct ev_loop *loop,
		const char *host, uint16_t port)
{
	struct network_server *ns = calloc(1, sizeof(*ns));
	if (ns == NULL) {
		return NULL;
	}

	ns->sin.sin6_family = AF_INET6;
	ns->sin.sin6_port = htons((uint16_t)port);
	ns->port = port;

	if (host == NULL) {
		ns->sin.sin6_addr = in6addr_any;
		ns->host = strdup("0.0.0.0");
	} else {
		// TODO bind to the specified host instead
		ns->sin.sin6_addr = in6addr_any;
		ns->host = strdup(host);
	}

	ns->listener = socket(AF_INET6, SOCK_STREAM, 0);
	if (ns->listener == -1) {
		goto err;
	}
	make_socket_nonblocking(ns->listener);

	/*
	 * SO_REUSEADDR means something different in windows
	 */
#ifndef _WIN32
	int yes = 1;
	setsockopt(ns->listener, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
#endif

	/*
	 * Override system default and allow socket to accept IPv4 and IPv6
	 */
#ifdef IPV6_V6ONLY
	int no = 0;
	setsockopt(ns->listener, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&no, sizeof(no));
#endif

	if (bind(ns->listener, (struct sockaddr *)&ns->sin, sizeof(ns->sin)) == -1) {
		goto err;
	}

	if (listen(ns->listener, 16) == -1) {
		goto err;
	}

	ev_io_init(&ns->connect_event, connect_cb, ns->listener, EV_READ);
	ns->connect_event.data = ns;
	ev_io_start(loop, &ns->connect_event);

	return ns;
err:
	network_server_free(ns);
	return NULL;
}

const char *network_server_get_host(struct network_server *ns)
{
	return ns->host;
}

uint16_t network_server_get_port(struct network_server *ns)
{
	return ns->port;
}

void network_server_free(struct network_server *ns)
{
	if (ns) {
		if (ns->listener) {
			close(ns->listener);
		}
		free(ns->host);
		free(ns);
	}
}




/**
 * Copyright 2016 Rapid7
 * @file network_server.h
 */

#include <stdlib.h>
#include <unistd.h>

#include <ev.h>
#include <arpa/inet.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <errno.h>
#include "bufferev.h"
#include "log.h"
#include "network_server.h"
#include "utils.h"

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
	socklen_t slen = sizeof(sockaddr);
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

int network_server_listen_tcp(struct network_server *ns,
	const char *host, uint16_t port)
{
	if (ns == NULL) {
		return -1;
	}
	int v6_only = 0;

	ns->sin.sin6_family = AF_INET6;
	ns->sin.sin6_port = htons((uint16_t)port);
	ns->port = port;

	if (host == NULL || strlen(host) == 0) {
		ns->sin.sin6_addr = in6addr_any;
		ns->host = strdup("::");
	} else {
		struct addrinfo *resolved_host = NULL;
		struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_flags = AI_NUMERICHOST,
		};
		if (getaddrinfo(host, NULL, &hints, &resolved_host) == 0) {
			if (resolved_host->ai_family == AF_INET) {
				char mapped_ipv6_address[INET6_ADDRSTRLEN];
				snprintf(mapped_ipv6_address, INET6_ADDRSTRLEN, "::ffff:%s", host);
				if (inet_pton(AF_INET6, mapped_ipv6_address, &ns->sin.sin6_addr) <= 0) {
					ns->sin.sin6_addr = in6addr_any;
				}
			} else if (resolved_host->ai_family == AF_INET6) {
				v6_only = 1;
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)resolved_host->ai_addr;
				memcpy(&ns->sin.sin6_addr, &ipv6->sin6_addr, resolved_host->ai_addrlen);
			}
			else {
				log_debug("unsupported address family: %d", resolved_host->ai_family);
				freeaddrinfo(resolved_host);
				goto err;
			}
			freeaddrinfo(resolved_host);
		}
		else {
			goto err;
		}
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
	setsockopt(ns->listener, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&v6_only, sizeof(v6_only));
#endif

	if (bind(ns->listener, (struct sockaddr *)&ns->sin, sizeof(ns->sin)) == -1) {
		goto err;
	}

	if (listen(ns->listener, 16) == -1) {
		goto err;
	}

	ev_io_init(&ns->connect_event, connect_cb, ns->listener, EV_READ);
	ns->connect_event.data = ns;
	ev_io_start(ns->loop, &ns->connect_event);
	return 0;

err:
	close(ns->listener);
	ns->listener = 0;
	return -1;
}

struct network_server * network_server_new(struct ev_loop *loop)
{
	struct network_server *ns = calloc(1, sizeof(*ns));
	if (ns == NULL) {
		return NULL;
	}
	ns->loop = loop;
	return ns;
}

static int network_server_stop(struct network_server *ns)
{
	if (ns->listener == 0) {
		return -1;
	}
	ev_io_stop(ns->loop, &ns->connect_event);
	close(ns->listener);
	ns->listener = 0;
	return 0;
}

void network_server_free(struct network_server *ns)
{
	if (ns) {
		log_debug("closing network server channel: %p", ns);
		network_server_stop(ns);
		if (ns->host) {
			free(ns->host);
		}
		free(ns);
	}
}

char * network_server_get_local_addr(struct network_server *ns, uint16_t *port)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	if (getsockname(ns->listener, (struct sockaddr *)&addr, &len) == -1) {
		return NULL;
	}

	return parse_sockaddr(&addr, port);
}
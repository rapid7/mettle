/**
 * Copyright 2015 Rapid7
 * @brief Durable multi-transport client network connection
 * @file network-client.h
 */

#include <ev.h>
#include <eio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "bufferev.h"
#include "buffer_queue.h"
#include "log.h"
#include "network_client.h"
#include "utils.h"

struct network_client_server {
	char *uri;
	enum network_proto proto;
	char *host;
	char *service;
};

struct network_client {
	struct ev_timer connect_timer;
	struct ev_loop *loop;
	struct network_client_server *servers;
	int num_servers;

	int curr_server;
	uint64_t connect_time_s;

	struct bufferev *be;
	struct addrinfo *addrinfo, *dst;
	struct addrinfo *src;
	char *src_addr;
	uint16_t src_port;

	enum {
		network_client_closed,
		network_client_resolving,
		network_client_connecting,
		network_client_connected,
	} state;

	int max_retries, retries;

	bufferev_data_cb read_cb;
	bufferev_data_cb write_cb;
	bufferev_event_cb event_cb;
	void *cb_arg;
};

void network_client_set_src(struct network_client *nc, const char *addr, uint16_t port)
{
	if (nc->src_addr) {
		free(nc->src_addr);
		nc->src_addr = NULL;
	}
	if (addr && strcmp(addr, "0.0.0.0")) {
		nc->src_addr = strdup(addr);
	}
	if (nc->src) {
		freeaddrinfo(nc->src);
		nc->src = NULL;
	}
	nc->src_port = port;
}

void server_free(struct network_client_server *srv)
{
	free(srv->host);
	free(srv->uri);
	free(srv->service);
	memset(srv, 0, sizeof(*srv));
}

int server_init(struct network_client_server *srv, const char *uri)
{
	int rc = -1;
	char *service = NULL;
	char *proto = NULL;
	char *uri_tmp = strdup(uri);
	char *host = strstr(uri_tmp, "://");

	memset(srv, 0, sizeof(*srv));
	srv->uri = strdup(uri);

	if (uri_tmp == NULL || srv->uri == NULL) {
		goto out;
	}

	if (host == NULL) {
		proto = "tcp";
		host = uri_tmp;
	} else {
		host[0] = '\0';
		proto = uri_tmp;
		host += 3;
	}

	if (proto == NULL || host == NULL) {
		log_error("failed to parse URI: %s", uri);
		goto out;
	}

	if (*host == '[') {
		host++;
		char *ipv6_end = host;
		while (*ipv6_end != 0 && *ipv6_end != ']') {
			ipv6_end++;
		}
		if (*ipv6_end == ']') {
			*ipv6_end = '\0';
		} else {
			log_error("invalid ipv6 address: %s", uri);
			goto out;
		}
		printf("%s\n", host);
		service = ipv6_end + 1;
		if (*service == ':' && service[1] != '\0') {
			service++;
		} else {
			service = NULL;
		}
	} else {
		service = strstr(host, ":");
		if (service) {
			service[0] = '\0';
			service++;
		}
	}

	srv->host = strdup(host);

	if (strcmp(proto, "udp") == 0) {
		srv->proto = network_proto_udp;
	} else if (strcmp(proto, "tcp") == 0) {
		srv->proto = network_proto_tcp;
	} else {
		log_error("unsupported protocol '%s'", proto);
		goto out;
	}

	if (service) {
		srv->service = strdup(service);
	} else {
		log_error("%s service unspecified", proto);
		goto out;
	}

	rc = 0;
out:
	if (rc != 0) {
		server_free(srv);
	}
	free(uri_tmp);

	return rc;
}

int
network_client_remove_servers(struct network_client *nc)
{
	if (nc->servers) {
		for (int i = 0; i < nc->num_servers; i++) {
			server_free(&nc->servers[i]);
		}
		free(nc->servers);
		nc->servers = NULL;
		nc->num_servers = 0;
	}
	return 0;
}

int
network_client_add_uri(struct network_client *nc, const char *uri)
{
	nc->servers = reallocarray(nc->servers, nc->num_servers + 1,
			sizeof(struct network_client_server));
	if (nc->servers == NULL) {
		return -1;
	}

	if (server_init(&nc->servers[nc->num_servers], uri) != 0) {
		return -1;
	}

	nc->num_servers++;
	return 0;
}

struct network_client_server *
get_curr_server(struct network_client *nc)
{
	if (nc->servers) {
		return &nc->servers[nc->curr_server];
	} else {
		return NULL;
	}
}

struct network_client_server *
choose_next_server(struct network_client *nc)
{
	if (nc->num_servers > 1) {
		nc->curr_server++;
		if (nc->curr_server >= nc->num_servers) {
			nc->curr_server = 0;
		}
	}
	return get_curr_server(nc);
}

ssize_t network_client_read(struct network_client *nc, void *buf, size_t buflen)
{
	return nc->be ? bufferev_read(nc->be, buf, buflen) : 0;
}

void * network_client_read_msg(struct network_client *nc, size_t *buflen)
{
	return nc->be ? bufferev_read_msg(nc->be, buflen) : NULL;
}

ssize_t network_client_write(struct network_client *nc, void *buf, size_t buflen)
{
	return nc->be ? bufferev_write(nc->be, buf, buflen) : 0;
}

static void set_closed(struct network_client *nc)
{
	nc->state = network_client_closed;

	if (nc->be) {
		bufferev_free(nc->be);
		nc->be = NULL;
	}
}

int network_client_stop(struct network_client *nc)
{
	if (nc->state != network_client_connected) {
		return -1;
	}
	set_closed(nc);
	return 0;
}

void network_client_set_cbs(struct network_client *nc,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg)
{
    nc->read_cb = read_cb;
    nc->write_cb = write_cb;
    nc->event_cb = event_cb;
    nc->cb_arg = cb_arg;
}

static void
client_connected(struct network_client *nc)
{
	nc->state = network_client_connected;
	struct network_client_server *srv = get_curr_server(nc);
	log_info("connected to '%s'", srv->uri);
}

static void on_read(struct bufferev *be, void *arg)
{
	struct network_client *nc = arg;

	if (nc->read_cb) {
		nc->read_cb(be, nc->cb_arg);
	}
}

static void connection_failed(struct network_client *nc)
{
	struct network_client_server *srv = get_curr_server(nc);
	log_info("failed to connect to '%s'", srv->uri);
	set_closed(nc);

	if (nc->max_retries >= 0 && nc->retries >= nc->max_retries) {
		ev_timer_stop(nc->loop, &nc->connect_timer);
		if (nc->event_cb) {
			nc->event_cb(NULL, BEV_ERROR, nc->cb_arg);
		}
	} else {
		nc->retries++;
	}
}

static void on_event(struct bufferev *be, int event, void *arg)
{
	struct network_client *nc = arg;

	if (event & BEV_CONNECTED) {
		client_connected(nc);
		if (nc->event_cb) {
			nc->event_cb(be, event, nc->cb_arg);
		}
	} else if (event & BEV_EOF) {
		set_closed(nc);
		if (nc->event_cb) {
			nc->event_cb(be, event, nc->cb_arg);
		}
	} else if (event & BEV_ERROR) {
		if (nc->state == network_client_connecting) {
			connection_failed(nc);
		}
	}
}

static void
log_addrinfo(const char *msg, struct addrinfo *ai)
{
	char host[INET6_ADDRSTRLEN] = { 0 };
	uint16_t port = 0;
	const char *proto = ai->ai_protocol == IPPROTO_UDP ? "udp" : "tcp";
	if (ai->ai_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, host, INET6_ADDRSTRLEN);
	} else if (ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
		port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, host, INET6_ADDRSTRLEN);
	}
	if (strchr(host, ':') != NULL) {
		log_info("%s %s://[%s]:%d", msg, proto, host, port);
	} else {
		log_info("%s %s://%s:%d", msg, proto, host, port);
	}
}

static int
on_resolve(struct eio_req *req)
{
	struct network_client *nc = req->data;
	struct network_client_server *srv = get_curr_server(nc);

	if (req->result != 0) {
		log_info("could not resolve '%s': %s",
			srv->uri, gai_strerror(req->result));
		nc->state = network_client_closed;
		return 0;
	}

	if (nc->dst == NULL) {
		nc->dst = nc->addrinfo;
	}

	bool failed = true;
	while (nc->dst) {
		log_addrinfo("connecting to", nc->dst);

		nc->state = network_client_connecting;
		nc->be = bufferev_new(nc->loop);
		if (nc->be) {
			bufferev_set_cbs(nc->be, on_read, NULL, on_event, nc);
			if (bufferev_connect_addrinfo(nc->be, nc->src, nc->dst, 1.0) == 0) {
				nc->dst = nc->dst->ai_next;
				failed = false;
				break;
			}
			bufferev_free(nc->be);
			nc->be = NULL;
		}
		nc->dst = nc->dst->ai_next;
	}

	if (nc->dst == NULL) {
		freeaddrinfo(nc->addrinfo);
		nc->addrinfo = NULL;
	}

	if (failed) {
		connection_failed(nc);
	}
	return 0;
}

int network_client_add_tcp_sock(struct network_client *nc, int sock)
{
	log_info("Adding opened socket %d", sock);
	nc->servers = reallocarray(nc->servers, nc->num_servers + 1,
			sizeof(struct network_client_server));
	if (nc->addrinfo) {
		return -1;
	}

	struct network_client_server *srv = &nc->servers[nc->num_servers++];
	memset(srv, 0, sizeof(struct network_client_server));

	char service[7];
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	getpeername(sock, (struct sockaddr *)&addr, &addr_len);

	srv->host = calloc(1, INET6_ADDRSTRLEN);
	if (srv->host == NULL) {
		log_error("Could not allocate host space");
		return -1;
	}

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &s->sin_addr, srv->host, INET6_ADDRSTRLEN);
		snprintf(service, sizeof(service), "%d", ntohs(s->sin_port));
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		inet_ntop(AF_INET6, &s->sin6_addr, srv->host, INET6_ADDRSTRLEN);
		snprintf(service, sizeof(service), "%d", ntohs(s->sin6_port));
	}

	srv->proto = network_proto_tcp;
	srv->service = strdup(service);

	if (nc->be == NULL) {
		nc->be = bufferev_new(nc->loop);
		if (nc->be) {
			bufferev_set_cbs(nc->be, on_read, NULL, on_event, nc);
			bufferev_connect_tcp_sock(nc->be, sock);
			client_connected(nc);
		}
	}

	return 0;
}

static void
resolve(struct eio_req *req)
{
	struct network_client *nc = req->data;
	if (nc->dst) {
		return;
	}

	struct network_client_server *srv = get_curr_server(nc);

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_flags = AI_CANONNAME,
	};

	if (srv->proto == network_proto_udp) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	log_info("resolving '%s'", srv->uri);

	nc->state = network_client_resolving;
	req->result = getaddrinfo(srv->host, srv->service, &hints, &nc->addrinfo);

	if ((nc->src_addr || nc->src_port) && nc->src == NULL) {
		if (nc->src_port > 0) {
			char port_buf[6];
			snprintf(port_buf, sizeof(port_buf), "%u", nc->src_port);
			getaddrinfo(nc->src_addr, port_buf, &hints, &nc->src);
		} else {
			getaddrinfo(nc->src_addr, NULL, &hints, &nc->src);
		}
	}
}

static void
reconnect_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct network_client *nc = w->data;

	if (nc->state != network_client_closed || nc->num_servers == 0) {
		return;
	}

	choose_next_server(nc);
	eio_custom(resolve, 0, on_resolve, nc);
}

int network_client_start(struct network_client *nc)
{
	ev_timer_start(nc->loop, &nc->connect_timer);
	return 0;
}

void network_client_set_retries(struct network_client *nc, int retries)
{
	nc->max_retries = retries;
}

void network_client_free(struct network_client *nc)
{
	if (nc) {
		if (nc->be) {
			bufferev_free(nc->be);
			nc->be = NULL;
		}
		ev_timer_stop(nc->loop, &nc->connect_timer);
		network_client_stop(nc);
		network_client_remove_servers(nc);
		free(nc->src_addr);
		if (nc->src) {
			freeaddrinfo(nc->src);
		}
		if (nc->addrinfo) {
			freeaddrinfo(nc->addrinfo);
		}
		free(nc);
	}
}

struct network_client * network_client_new(struct ev_loop *loop)
{
	struct network_client *nc = calloc(1, sizeof(*nc));
	if (nc) {
		nc->loop = loop;
		nc->state = network_client_closed;
		nc->max_retries = -1;
		ev_timer_init(&nc->connect_timer, reconnect_cb, 0, 1.0);
		nc->connect_timer.data = nc;
	}
	return nc;
}

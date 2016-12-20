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

#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#endif
#include <unistd.h>

#include "bufferev.h"
#include "buffer_queue.h"
#include "log.h"
#include "network_client.h"
#include "util.h"

struct network_client_server {
	char *uri;
	enum network_proto proto;
	char *host;
	char **services;
	int num_services;
};

struct network_client {
	struct ev_timer connect_timer;
	struct ev_loop *loop;
	struct network_client_server *servers;
	int num_servers;

	int curr_server, curr_service;
	uint64_t connect_time_s;

	struct bufferev *be;
	struct addrinfo *addrinfo;

	enum {
		network_client_closed,
		network_client_resolving,
		network_client_connecting,
		network_client_connected,
	} state;

	int max_retries, retries;

	network_client_cb_t connect_cb;
	void *connect_cb_arg;
	network_client_cb_t read_cb;
	void *read_cb_arg;
	network_client_cb_t error_cb;
	void *error_cb_arg;
	network_client_cb_t close_cb;
	void *close_cb_arg;
};

void server_free(struct network_client_server *srv)
{
	free(srv->host);
	free(srv->uri);
	for (int i = 0; i < srv->num_services; i++) {
		free(srv->services[i]);
	}
	free(srv->services);
	memset(srv, 0, sizeof(*srv));
}

int add_server_service(struct network_client_server *srv, const char *service)
{
	char *service_cpy = strdup(service);
	if (service_cpy == NULL) {
		return -1;
	}
	srv->services = reallocarray(srv->services,
			srv->num_services + 1, sizeof(char *));
	if (srv->services == NULL) {
		return -1;
	}
	srv->services[srv->num_services++] = service_cpy;
	return 0;
}

int init_server(struct network_client_server *srv, const char *uri)
{
	int rc = -1;
	char *services = NULL;
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

	services = strstr(host, ":");
	if (services) {
		services[0] = '\0';
		services++;
	}

	if (proto == NULL || host == NULL) {
		log_error("failed to parse URI: %s", uri);
		goto out;
	}

	srv->host = strdup(host);
	srv->proto = network_str_to_proto(proto);

	if (services) {
		char *services_tmp = strdup(services);
		if (!services_tmp) {
			goto out;
		}

		char *service_tmp = services_tmp;
		const char *service;
		while ((service = strsep(&service_tmp, ",")) != NULL) {
			if (add_server_service(srv, service) != 0) {
				free(services_tmp);
				goto out;
			}
		}
		free(services_tmp);
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

	if (init_server(&nc->servers[nc->num_servers], uri) != 0) {
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

const char *
get_curr_service(struct network_client *nc)
{
	if (nc->servers) {
		return nc->servers[nc->curr_server].services[nc->curr_service];
	} else {
		return 0;
	}
}

struct network_client_server *
choose_next_server(struct network_client *nc)
{
	struct network_client_server *srv = get_curr_server(nc);
	if (srv && nc->curr_service < srv->num_services - 1) {
		nc->curr_service++;
	} else {
		nc->curr_service = 0;
		if (nc->num_servers > 1) {
			nc->curr_server++;
			if (nc->curr_server >= nc->num_servers) {
				nc->curr_server = 0;
			}
		}
	}
	return get_curr_server(nc);
}

struct buffer_queue * network_client_rx_queue(struct network_client *nc)
{
	return bufferev_rx_queue(nc->be);
}

size_t network_client_peek(struct network_client *nc, void *buf, size_t buflen)
{
	return nc->be ? bufferev_peek(nc->be, buf, buflen) : 0;
}

size_t network_client_read(struct network_client *nc, void *buf, size_t buflen)
{
	return nc->be ? bufferev_read(nc->be, buf, buflen) : 0;
}

size_t network_client_bytes_available(struct network_client *nc)
{
	return nc->be ? bufferev_bytes_available(nc->be) : 0;
}

ssize_t network_client_write(struct network_client *nc, void *buf, size_t buflen)
{
	return nc->be ? bufferev_write(nc->be, buf, buflen) : 0;
}

static void set_closed(struct network_client *nc)
{
	nc->state = network_client_closed;

	if (nc->addrinfo) {
		freeaddrinfo(nc->addrinfo);
		nc->addrinfo = NULL;
	}

	if (nc->be) {
		bufferev_free(nc->be);
		nc->be = NULL;
	}
}

int network_client_close(struct network_client *nc)
{
	if (nc->state != network_client_connected) {
		return -1;
	}
	set_closed(nc);
	return 0;
}

void network_client_set_read_cb(struct network_client *nc,
	network_client_cb_t cb, void *arg)
{
	nc->read_cb = cb;
	nc->read_cb_arg = arg;
}

void network_client_set_connect_cb(struct network_client *nc,
	network_client_cb_t cb, void *arg)
{
	nc->connect_cb = cb;
	nc->connect_cb_arg = arg;
}

void network_client_set_error_cb(struct network_client *nc,
	network_client_cb_t cb, void *arg)
{
	nc->error_cb = cb;
	nc->error_cb_arg = arg;
}

void network_client_set_close_cb(struct network_client *nc,
	network_client_cb_t cb, void *arg)
{
	nc->close_cb = cb;
	nc->close_cb_arg = arg;
}

void client_connected(struct network_client *nc)
{
	nc->state = network_client_connected;
	struct network_client_server *srv = get_curr_server(nc);
	log_info("connected to '%s://%s:%s'",
		network_proto_to_str(srv->proto), srv->host, get_curr_service(nc));
}

static void on_connect(struct bufferev *be, void *arg)
{
	struct network_client *nc = arg;
	client_connected(nc);
	if (nc->connect_cb) {
		nc->connect_cb(nc, nc->connect_cb_arg);
	}
}

static void on_read(struct bufferev *be, void *arg)
{
	struct network_client *nc = arg;
	if (nc->read_cb) {
		nc->read_cb(nc, nc->read_cb_arg);
	}
}

static void on_error(struct bufferev *be, void *arg)
{
	struct network_client *nc = arg;

	if (nc->state == network_client_connecting) {
		struct network_client_server *srv = get_curr_server(nc);
		log_info("failed to connect to '%s://%s:%s'",
				network_proto_to_str(srv->proto), srv->host, get_curr_service(nc));
		set_closed(nc);

		if (nc->max_retries >= 0 && nc->retries >= nc->max_retries) {
			ev_timer_stop(nc->loop, &nc->connect_timer);
			if (nc->error_cb) {
				nc->error_cb(nc, nc->error_cb_arg);
			}
		} else {
			nc->retries++;
		}
	}
}

static void on_close(struct bufferev *be, void *arg)
{
	struct network_client *nc = arg;
	set_closed(nc);
	if (nc->close_cb) {
		nc->close_cb(nc, nc->close_cb_arg);
	}
}

static void set_bufferev_cbs(struct network_client *nc)
{
	if (nc->be) {
		bufferev_set_read_cb(nc->be, on_read, nc);
		bufferev_set_connect_cb(nc->be, on_connect, nc);
		bufferev_set_error_cb(nc->be, on_error, nc);
		bufferev_set_close_cb(nc->be, on_close, nc);
	}
}

static int
on_resolve(struct eio_req *req)
{
	struct network_client *nc = req->data;
	char ipstr[INET6_ADDRSTRLEN];
	struct network_client_server *srv = get_curr_server(nc);

	if (req->result != 0) {
		log_info("could not resolve '%s://%s:%s': %s",
			network_proto_to_str(srv->proto), srv->host, get_curr_service(nc),
			gai_strerror(req->result));
		set_closed(nc);
		return -1;
	}

	for (struct addrinfo *p = nc->addrinfo; p; p = p->ai_next) {
		void *addr;

		if (p->ai_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &ipv4->sin_addr;
		} else {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &ipv6->sin6_addr;
		}

		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);

		nc->state = network_client_connecting;

		nc->be = bufferev_new(nc->loop);
		set_bufferev_cbs(nc);

		if (bufferev_connect_addrinfo(nc->be, p, 1.0) == 0) {
			return 0;
		} else {
			bufferev_free(nc->be);
			nc->be = NULL;
		}
	}

	set_closed(nc);
	return 0;
}

int network_client_add_tcp_sock(struct network_client *nc, int sock)
{
	log_info("Adding opened socket %d", sock);
	nc->servers = reallocarray(nc->servers, nc->num_servers + 1,
			sizeof(struct network_client_server));
	if (nc->servers == NULL) {
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

	add_server_service(srv, service);

	if (nc->be == NULL) {
		nc->be = bufferev_new(nc->loop);
		set_bufferev_cbs(nc);
		bufferev_connect_tcp_sock(nc->be, sock);
		client_connected(nc);
	}

	return 0;
}

static void
resolve(struct eio_req *req)
{
	struct network_client *nc = req->data;
	struct network_client_server *srv = get_curr_server(nc);
	const char *service = get_curr_service(nc);

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

	log_info("resolving %s://%s:%s",
			network_proto_to_str(srv->proto), srv->host, service);

	nc->state = network_client_resolving;
	req->result = getaddrinfo(srv->host, service, &hints, &nc->addrinfo);
}

static void
reconnect_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct network_client *nc = (struct network_client *)w;

	if (nc->state != network_client_closed || nc->num_servers == 0) {
		return;
	}

	choose_next_server(nc);
	eio_custom(resolve, 0, on_resolve, nc);
}

int network_client_start(struct network_client *nc)
{
	ev_timer_init(&nc->connect_timer, reconnect_cb, 0, 1.0);
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
		network_client_close(nc);
		network_client_remove_servers(nc);
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
	}
	return nc;
}

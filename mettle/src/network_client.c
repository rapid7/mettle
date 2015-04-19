/**
 * @brief Durable multi-transport client connection abtraction
 */

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"
#include "network_client.h"
#include "util.h"

enum network_client_proto {
	network_client_proto_udp,
	network_client_proto_tcp,
	network_client_proto_tls,
	network_client_proto_http,
	network_client_proto_https
};

struct network_client_server {
	char *uri;
	enum network_client_proto proto;
	char *host;
	char **services;
	int num_services;
};

struct network_client {
	uv_loop_t *loop;
	uv_timer_t connect_timer;
	struct network_client_server *servers;
	int num_servers;

	int curr_server, curr_service;
	uint64_t connect_time_s;

	union uv_any_handle conn;

	enum {
		network_client_connected,
		network_client_resolving,
		network_client_connecting,
		network_client_disconnected,
	} state;
};

struct {
	enum network_client_proto proto;
	const char *str;
} proto_list[] = {
	{network_client_proto_udp, "udp"},
	{network_client_proto_tcp, "tcp"},
	{network_client_proto_tls, "tls"},
	{network_client_proto_http, "http"},
	{network_client_proto_https, "https"},
};

static const char *proto_to_str(enum network_client_proto proto)
{
	for (int i = 0; i < COUNT_OF(proto_list); i++) {
		if (proto_list[i].proto == proto) {
			return proto_list[i].str;
		}
	}
	return "unknown";
}

static enum network_client_proto str_to_proto(const char *proto)
{
	for (int i = 0; i < COUNT_OF(proto_list); i++) {
		if (!strcasecmp(proto_list[i].str, proto)) {
			return proto_list[i].proto;
		}
	}
	return network_client_proto_tcp;
}

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

static int add_server_service(struct network_client_server *srv, const char *service)
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

static int parse_server(struct network_client_server *srv, const char *uri)
{
	int rc = -1;
	char *services = NULL;
	char *proto = NULL;
	char *uri_tmp = strdup(uri);
	char *host = strstr(uri_tmp, "://");
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
	srv->proto = str_to_proto(proto);

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
	} else {
		switch (srv->proto) {
			case network_client_proto_http:
				add_server_service(srv, "80");
				break;
			case network_client_proto_https:
				add_server_service(srv, "443");
				break;
			default:
				log_error("%s service unspecified", proto);
				goto out;
		}
	}

	rc = 0;
out:
	if (rc != 0) {
		server_free(srv);
	}
	free(uri_tmp);

	return rc;
}

int network_client_remove_servers(struct network_client *nc)
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

int network_client_add_server(struct network_client *nc, const char *uri)
{
	nc->servers = reallocarray(nc->servers, nc->num_servers + 1,
			sizeof(struct network_client_server));
	if (nc->servers == NULL) {
		return -1;
	}

	if (parse_server(&nc->servers[nc->num_servers], uri) != 0) {
		return -1;
	}

	nc->num_servers++;
	return 0;
}

static struct network_client_server *get_curr_server(struct network_client *nc)
{
	if (nc->servers) {
		return &nc->servers[nc->curr_server];
	} else {
		return NULL;
	}
}

static const char * get_curr_service(struct network_client *nc)
{
	if (nc->servers) {
		return nc->servers[nc->curr_server].services[nc->curr_service];
	} else {
		return 0;
	}
}

static struct network_client_server *choose_next_server(struct network_client *nc)
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

static void on_close(uv_handle_t *req)
{
	struct network_client *nc = req->data;
	nc->state = network_client_disconnected;
}

static void on_write(uv_write_t *req, int status)
{
	struct network_client *nc = req->data;
	if (status == -1) {
		log_error("failed to write");
		return;
	}

	uv_close((uv_handle_t *)&nc->conn, on_close);
}

static void connect_cb(uv_connect_t *req, int status)
{
	struct network_client *nc = req->data;
	struct network_client_server *srv = get_curr_server(nc);

	if (status != 0) {
		log_info("failed to connect to '%s://%s:%s': %s",
				proto_to_str(srv->proto), srv->host, get_curr_service(nc),
				uv_strerror(status));
		nc->state = network_client_disconnected;
		return;
	}

	uv_buf_t msg;
	if (uv_buf_strdup(&msg, "hello world")) {
		log_error("uv_buf_strdup failed");
		return;
	}

	uv_write_t write_req = { .data = nc };
	uv_write(&write_req, req->handle, &msg, 1, on_write);
}

static int connect_tcp(struct network_client *nc, struct addrinfo *addrinfo)
{
	uv_connect_t req  = { .data = nc };
	uv_tcp_init(nc->loop, &nc->conn.tcp);
	nc->conn.tcp.data = nc;
	return uv_tcp_connect(&req, &nc->conn.tcp,
			(const struct sockaddr *)addrinfo->ai_addr, connect_cb);
}

static void on_send(uv_udp_send_t *req, int status)
{
	struct network_client *nc = req->data;
	uv_close((uv_handle_t *)&nc->conn, on_close);
}

static int connect_udp(struct network_client *nc, struct addrinfo *addrinfo)
{
	uv_udp_init(nc->loop, &nc->conn.udp);

	uv_buf_t msg;
	if (uv_buf_strdup(&msg, "hello world")) {
		log_error("uv_buf_strdup failed");
		return -1;
	}

	uv_udp_send_t send_req = { .data = nc };
	return uv_udp_send(&send_req, &nc->conn.udp, &msg, 1,
			(const struct sockaddr *)addrinfo->ai_addr, on_send);

}

void resolving_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrinfo)
{
	struct network_client *nc = req->data;
	struct network_client_server *srv = get_curr_server(nc);

	if (status < 0) {
		log_info("could not resolve '%s://%s:%s': %s",
				proto_to_str(srv->proto), srv->host, get_curr_service(nc),
				uv_strerror(status));
		nc->state = network_client_disconnected;
		return;
	}

	switch (srv->proto) {

		case network_client_proto_udp:
			if (connect_udp(nc, addrinfo) == 0) {
				nc->state = network_client_connected;
			} else {
				nc->state = network_client_disconnected;
			}
			break;

		case network_client_proto_tcp:
			if (connect_tcp(nc, addrinfo) == 0) {
				nc->state = network_client_connecting;
			} else {
				nc->state = network_client_disconnected;
			}
			break;

		case network_client_proto_tls:
		case network_client_proto_http:
		case network_client_proto_https:
			log_info("proto %s not supported for %s://%s:%s",
				proto_to_str(srv->proto), proto_to_str(srv->proto), srv->host,
				get_curr_service(nc), uv_strerror(status));
			nc->state = network_client_disconnected;
			break;
	}
}

static void reconnect_cb(uv_timer_t *timer)
{
	struct network_client *nc = timer->data;

	if (nc->state != network_client_disconnected || nc->num_servers == 0) {
		return;
	}

	struct network_client_server *srv = choose_next_server(nc);
	const char *service = get_curr_service(nc);

	log_info("connecting to %s://%s:%s",
			proto_to_str(srv->proto), srv->host, service);

	uv_getaddrinfo_t req = { .data = nc };

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_flags = AI_CANONNAME,
	};

	if (srv->proto == network_client_proto_udp) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	nc->state = network_client_resolving;
	uv_getaddrinfo(nc->loop, &req, resolving_cb, srv->host, service, &hints);
}

int network_client_start(struct network_client *nc)
{
	if (uv_timer_init(nc->loop, &nc->connect_timer) != 0) {
		return -1;
	}

	return uv_timer_start(&nc->connect_timer, reconnect_cb, 0, 1000);
}

int network_client_stop(struct network_client *nc)
{
	uv_timer_stop(&nc->connect_timer);
	return 0;
}

void network_client_free(struct network_client *nc)
{
	if (nc) {
		network_client_stop(nc);
		network_client_remove_servers(nc);
		free(nc);
	}
}

struct network_client * network_client(uv_loop_t *loop)
{
	struct network_client *nc = calloc(1, sizeof(*nc));
	if (!nc) {
		return NULL;
	}

	if (loop == NULL) {
		loop = uv_default_loop();
		if (!loop) {
			goto err;
		}
	}

	nc->loop = loop;

	uv_timer_init(nc->loop, &nc->connect_timer);
	nc->connect_timer.data = nc;

	nc->state = network_client_disconnected;

	return nc;

err:
	network_client_free(nc);
	return NULL;
}

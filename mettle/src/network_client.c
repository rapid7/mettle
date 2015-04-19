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
	uint16_t *ports;
	int num_ports;
};

struct network_client {
	uv_loop_t *loop;
	uv_timer_t connect_timer;
	struct network_client_server *servers;
	int num_servers;

	int curr_server, curr_port;
	uint64_t connect_time_s;

	union {
		uv_tcp_t tcp;
		uv_udp_t udp;
	} conn;
};

/*
uv_buf_t uv_buf_alloc(uv_handle_t *handle, size_t size)
{
	return uv_buf_init(malloc(size), size);
}

int uv_buf_dup(uv_buf_t *buf, void *base, size_t len)
{
	void *copy = malloc(len);
	if (copy) {
		*buf = uv_buf_alloc(NULL, len);
		memcpy(buf->base, base, len);
		return 0;
	}
	return -1;
}

void uv_buf_free(uv_buf_t *buf)
{
	free(buf->base);
	buf->base = NULL;
	buf->len = 0;
}

int uv_buf_strdup(uv_buf_t *buf, void *str)
{
	return uv_buf_dup(buf, str, strlen(str) + 1);
}

void on_write(uv_write_t *req, int status)
{
	if (status == -1) {
		log_error("failed to write");
		return;
	}
}

void on_connect(uv_connect_t *req, int status)
{
	if (status != 0) {
		log_error("failed to connect: %s", uv_strerror(status));
		return;
	}

	uv_buf_t msg;
	if (uv_buf_strdup(&msg, "hello world")) {
		log_error("uv_buf_strdup failed");
		return;
	}

	uv_write_t write_req;
	uv_write(&write_req, req->handle, &msg, 1, on_write);
}

struct mettle_conn * mettle_conn_open(struct mettle *m, const char *addr, uint16_t port)
{
	struct mettle_conn *conn = calloc(1, sizeof(*conn));

	union {
		struct sockaddr_in6 addr6;
		struct sockaddr_in addr4;
		struct sockaddr addr;
	} dest;

	if (conn) {
		uv_tcp_init(m->loop, &conn->socket);
		uv_tcp_keepalive(&conn->socket, 1, 60);
		uv_ip4_addr(addr, port, &dest.addr4);
		conn->m = m;
		conn->req.data = conn;

		uv_tcp_connect(&conn->req, &conn->socket, &dest.addr, on_connect);
	}

	return conn;
}
*/

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
	free(srv->ports);
	memset(srv, 0, sizeof(*srv));
}

static int add_server_port(struct network_client_server *srv, uint16_t port_num)
{
	srv->ports = reallocarray(srv->ports,
			srv->num_ports + 1, sizeof(uint16_t));
	if (srv->ports == NULL) {
		return -1;
	}
	srv->ports[srv->num_ports++] = port_num;
	return 0;
}

static int parse_server(struct network_client_server *srv, const char *uri)
{
	int rc = -1;
	char *ports = NULL;
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

	ports = strstr(host, ":");
	if (ports) {
		ports[0] = '\0';
		ports++;
	}

	if (proto == NULL || host == NULL) {
		log_error("failed to parse URI: %s", uri);
		goto out;
	}

	srv->host = strdup(host);
	srv->proto = str_to_proto(proto);

	if (ports) {
		char *ports_tmp = strdup(ports);
		if (!ports_tmp) {
			goto out;
		}

		char *port_tmp = ports_tmp;
		const char *port;
		while ((port = strsep(&port_tmp, ",")) != NULL) {
			const char *err;
			uint16_t port_num = strtonum(port, 1, UINT16_MAX, &err);
			if (err) {
				log_error("port out of range: %s", err);
				free(ports_tmp);
				goto out;
			}
			if (add_server_port(srv, port_num) != 0) {
				free(ports_tmp);
				goto out;
			}
		}
	} else {
		switch (srv->proto) {
			case network_client_proto_http:
				add_server_port(srv, 80);
				break;
			case network_client_proto_https:
				add_server_port(srv, 443);
				break;
			default:
				log_error("%s port unspecified", proto);
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

static uint16_t get_curr_port(struct network_client *nc)
{
	if (nc->servers) {
		return nc->servers[nc->curr_server].ports[nc->curr_port];
	} else {
		return 0;
	}
}

static void choose_next_server(struct network_client *nc)
{
	struct network_client_server *srv = get_curr_server(nc);
	if (srv && nc->curr_port < srv->num_ports - 1) {
		nc->curr_port++;
	} else {
		nc->curr_port = 0;
		if (nc->num_servers > 1) {
			nc->curr_server++;
			if (nc->curr_server >= nc->num_servers) {
				nc->curr_server = 0;
			}
		}
	}
}

static void connect_cb(uv_timer_t *timer)
{
	struct network_client *nc = timer->data;

	choose_next_server(nc);

	struct network_client_server *srv = get_curr_server(nc);
	uint16_t port = get_curr_port(nc);

	log_info("Connecting to %s://%s:%u",
			proto_to_str(srv->proto), srv->host, port);
}

int network_client_start(struct network_client *nc)
{
	if (uv_timer_init(nc->loop, &nc->connect_timer) != 0) {
		return -1;
	}

	return uv_timer_start(&nc->connect_timer, connect_cb, 0, 1000);
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

	return nc;

err:
	network_client_free(nc);
	return NULL;
}

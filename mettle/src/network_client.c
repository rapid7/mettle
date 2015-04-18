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
	char *hostname;
	uint16_t *ports;
	int num_ports;
};

struct network_client {
	uv_loop_t *loop;
	uv_timer_t connect_timer;
	struct network_client_server *servers;
	int num_servers;
};

enum network_client_proto str_to_proto(const char *proto)
{
	struct {
		enum network_client_proto proto;
		const char *str;
	} protos[] = {
		{network_client_proto_udp, "udp"},
		{network_client_proto_tcp, "tcp"},
		{network_client_proto_tls, "tls"},
		{network_client_proto_http, "http"},
		{network_client_proto_https, "https"},
	};

	for (int i = 0; i < COUNT_OF(protos); i++) {
		if (!strcasecmp(protos[i].str, proto)) {
			return protos[i].proto;
		}
	}

	return network_client_proto_tcp;
}

void server_free(struct network_client_server *srv)
{
	free(srv->hostname);
	free(srv->uri);
	free(srv->ports);
	memset(srv, 0, sizeof(*srv));
}

static int parse_server(struct network_client_server *srv, const char *uri)
{
	int rc = -1;
	srv->uri = strdup(uri);
	if (srv->uri == NULL) {
		goto out;
	}

	char *ports = NULL;
	char *proto = NULL;
	char *uri_tmp = strdup(uri);
	char *host = strstr(uri_tmp, "://");

	if (host == NULL) {
		proto = "tcp";
		host = uri_tmp;
	} else {
		uri_tmp[3] = '\0';
		proto = uri_tmp;
		host += 3;
	}

	ports = strstr(host, ":");
	if (ports) {
		ports[0] = '\0';
		ports++;
	}

	if (proto == NULL || host == NULL || ports == NULL) {
		log_error("failed to parse URI: %s", uri);
		goto out;
	}

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
			goto out;
		}
		srv->ports = reallocarray(srv->ports,
				srv->num_ports + 1, sizeof(uint16_t));
		if (srv->ports == NULL) {
			goto out;
		}
		srv->ports[srv->num_ports++] = port_num;
	}

	srv->proto = str_to_proto(proto);
	srv->hostname = strdup(host);

	rc = 0;
out:
	if (rc != 0) {
		server_free(srv);
	}
	free(ports_tmp);
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

	if (parse_server(&nc->servers[nc->num_servers], uri) == -1) {
		return -1;
	}

	nc->num_servers++;
	return 0;
}

void network_client_free(struct network_client *nc)
{
	if (nc) {
		uv_timer_stop(&nc->connect_timer);
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

	if (uv_timer_init(nc->loop, &nc->connect_timer) != 0) {
		goto err;
	}

	return nc;

err:
	network_client_free(nc);
	return NULL;
}

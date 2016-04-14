/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sigar.h>
#include <uv.h>

#include "log.h"
#include "network_client.h"
#include "mettle.h"
#include "tlv.h"

struct mettle {
	struct network_client *nc;
	struct tlv_dispatcher *td;

	sigar_t *sigar;
	char fqdn[SIGAR_MAXDOMAINNAMELEN];
	uv_loop_t *loop;
	uv_timer_t heartbeat;
};

void heartbeat_cb(uv_timer_t *handle)
{
	log_info("Heartbeat");
}

int start_heartbeat(struct mettle *m)
{
	uv_timer_init(m->loop, &m->heartbeat);
	m->heartbeat.data = m;
	uv_timer_start(&m->heartbeat, heartbeat_cb, 0, 60000);
	return 0;
}

int mettle_add_server_uri(struct mettle *m, const char *uri)
{
	return network_client_add_server(m->nc, uri);
}

uv_loop_t * mettle_get_loop(struct mettle *m)
{
	return m->loop;
}

const char *mettle_get_fqdn(struct mettle *m)
{
	return m->fqdn;
}

struct tlv_dispatcher *mettle_get_tlv_dispatcher(struct mettle *m)
{
	return m->td;
}

sigar_t *mettle_get_sigar(struct mettle *m)
{
	return m->sigar;
}

void mettle_free(struct mettle *m)
{
	if (m) {
		tlv_dispatcher_free(m->td);
		network_client_free(m->nc);
		free(m);
	}
}

static void on_tlv_response(struct tlv_dispatcher *td, void *arg)
{
	struct mettle *m = arg;
	void *buf;
	size_t len;

	while ((buf = tlv_dispatcher_dequeue_response(td, &len))) {
		network_client_write(m->nc, buf, len);
		free(buf);
	}
}

static void on_network_read(struct network_client *nc, void *arg)
{
	struct mettle *m = arg;
	struct buffer_queue *q = network_client_rx_queue(nc);
	struct tlv_packet *request;

	while ((request = tlv_packet_read_buffer_queue(q))) {
		tlv_dispatcher_process_request(m->td, request);
	}
}

struct mettle *mettle(void)
{
	struct mettle *m = calloc(1, sizeof(*m));

	if (m == NULL) {
		return NULL;
	}

	m->loop = uv_default_loop();

	start_heartbeat(m);

	m->nc = network_client_new(m->loop);
	if (m->nc == NULL) {
		goto err;
	}

	if (sigar_open(&m->sigar) == -1) {
		goto err;
	}

	sigar_fqdn_get(m->sigar, m->fqdn, sizeof(m->fqdn));

	network_client_set_read_cb(m->nc, on_network_read, m);

	m->td = tlv_dispatcher_new(on_tlv_response, m);
	if (m->td == NULL) {
		goto err;
	}

	tlv_register_coreapi(m, m->td);
	tlv_register_stdapi(m, m->td);

	return m;

err:
	mettle_free(m);
	return NULL;
}

int mettle_start(struct mettle *m)
{
	network_client_start(m->nc);

	return uv_run(m->loop, UV_RUN_DEFAULT);
}

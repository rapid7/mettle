/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "log.h"
#include "network_client.h"
#include "mettle.h"
#include "tlv.h"

struct mettle {
	struct network_client *nc;
	struct tlv_dispatcher *td;

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

static void on_read(struct network_client *nc, void *arg)
{
	struct mettle *m = arg;
	struct buffer_queue *q = network_client_rx_queue(nc);
	struct tlv_packet *request;

   	while ((request = tlv_get_packet_buffer_queue(q))) {
		struct tlv_packet *p = tlv_process_request(m->td, request);
		if (p) {
			network_client_write(nc, tlv_packet_data(p), tlv_packet_len(p));
			tlv_packet_free(p);
		}
	}
}

int mettle_add_server_uri(struct mettle *m, const char *uri)
{
	return network_client_add_server(m->nc, uri);
}

void mettle_free(struct mettle *m)
{
	if (m) {
		network_client_free(m->nc);

		free(m);
	}
}

struct tlv_packet *core_machine_id(struct tlv_handler_ctx *ctx, void *arg)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	p = tlv_packet_add_str(p, TLV_TYPE_MACHINE_ID, "Hello");
	return p;
}

struct tlv_packet *core_enumextcmd(struct tlv_handler_ctx *ctx, void *arg)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	p = tlv_packet_add_str(p, TLV_TYPE_STRING, "stdapi");
	return p;
}

void register_core_api(struct mettle *m, struct tlv_dispatcher *td)
{
	tlv_dispatcher_add_handler(td, "core_enumextcmd", core_enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", core_machine_id, m);
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

	network_client_set_read_cb(m->nc, on_read, m);

	m->td = tlv_dispatcher_new();
	if (m->td == NULL) {
		goto err;
	}

	register_core_api(m, m->td);

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

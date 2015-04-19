#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "log.h"
#include "mettle.h"
#include "network_client.h"

struct mettle {
	int version;
	uv_loop_t *loop;

	struct network_client *nc;

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
	uv_timer_start(&m->heartbeat, heartbeat_cb, 0, 1000);
	return 0;
}

struct mettle *mettle(void)
{
	struct mettle *m = calloc(1, sizeof(*m));

	if (m == NULL) {
		return NULL;
	}

	m->loop = uv_default_loop();

	start_heartbeat(m);

	m->nc = network_client(m->loop);
	if (m->nc == NULL) {
		return NULL;
	}

	network_client_add_server(m->nc, "udp://localhost:4444");
	network_client_add_server(m->nc, "tcp://localhost:4444,4445");
	network_client_add_server(m->nc, "http://127.0.0.1:8080");
	network_client_add_server(m->nc, "https://127.0.0.1:4343");

	return m;
}

int mettle_start(struct mettle *m)
{
	network_client_start(m->nc);

	return uv_run(m->loop, UV_RUN_DEFAULT);
}

void mettle_free(struct mettle *m)
{
	free(m->nc);
	free(m);
}

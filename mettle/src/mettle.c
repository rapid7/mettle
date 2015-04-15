#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "mettle.h"

struct mettle_conn {
	struct mettle *m;
	uv_tcp_t socket;
	uv_connect_t req;

	union {
		struct sockaddr_in6 addr6;
		struct sockaddr_in addr4;
		struct sockaddr addr;
	} dest;
};

struct mettle {
	int version;
	uv_loop_t *loop;

	uv_timer_t heartbeat;
	struct mettle_conn *conn;
};

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
		mettle_log("failed to write");
		return;
	}
}

void on_connect(uv_connect_t *req, int status)
{
	if (status == -1) {
		mettle_log("failed to connect");
		return;
	}

	uv_buf_t msg;
	if (uv_buf_strdup(&msg, "hello world")) {
		mettle_log("uv_buf_strdup failed");
		return;
	}

	mettle_log("connected!");

	uv_stream_t *tcp = req->handle;
	uv_write_t write_req;
	uv_write(&write_req, tcp, &msg, 1, on_write);
}

struct mettle_conn * mettle_conn_open(struct mettle *m, const char *addr, uint16_t port)
{
	struct mettle_conn *conn = calloc(1, sizeof(*conn));

	if (conn) {
		/*
		 * Initialize
		 */
		uv_tcp_init(m->loop, &conn->socket);
		uv_tcp_keepalive(&conn->socket, 1, 60);
		uv_ip4_addr(addr, port, &conn->dest.addr4);
		conn->m = m;
		conn->req.data = conn;

		/*
		 * Setup initial connection event
		 */
		uv_tcp_connect(&conn->req, &conn->socket, &conn->dest.addr, on_connect);
	}

	return conn;
}

void heartbeat_cb(uv_timer_t *handle)
{
	mettle_log("Heartbeat");
	struct mettle *m = handle->data;
	mettle_conn_open(m, "127.0.0.1", 4444);
}

struct mettle *mettle_open(void)
{
	struct mettle *m = calloc(1, sizeof(*m));

	if (m == NULL) {
		return NULL;
	}

    mettle_log_init_file(stderr);
    mettle_log_init_flush_thread();

	m->loop = uv_default_loop();

	uv_timer_init(m->loop, &m->heartbeat);
	m->heartbeat.data = m;
	uv_timer_start(&m->heartbeat, heartbeat_cb, 0, 1000);

	return m;
}

int mettle_start(struct mettle *m)
{
	return uv_run(m->loop, UV_RUN_DEFAULT);
}

void mettle_close(struct mettle *m)
{
	free(m);
}

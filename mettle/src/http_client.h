#ifndef METTLE_HTTP_CLIENT_H
#define METTLE_HTTP_CLIENT_H

#include <ev.h>

enum http_request {
	http_request_get,
	http_request_post,
	http_request_put,
	http_request_delete
};

enum http_auth_type {
	http_auth_none,
	http_auth_basic,
	http_auth_digest
};

enum http_ca_type {
	http_ca_type_none,
	http_ca_type_path,
	http_ca_type_bundle
};

enum http_proxy_type {
	http_proxy_none,
	http_proxy_http,
	http_proxy_socks5
};

struct http_request_data {

	char * const *headers;
	int num_headers;

	char *cookie_list;
	char *referer;
	char *ua;

#define HTTP_DATA_COMPRESS (1 << 0)
	unsigned int flags;
	const char *content_type;
	void *content;
	size_t content_len;
};

struct http_request_opts {

	enum http_ca_type ca_type;
	const char *ca;

	struct {
		enum http_proxy_type type;
		const char *hostname;
		uint16_t port;
		enum http_auth_type auth_type;
		const char *auth_user;
		const char *auth_pass;
	} proxy;

#define HTTP_OPTS_VERBOSE             (1 << 0)
#define HTTP_OPTS_SKIP_TLS_VALIDATION (1 << 1)
	unsigned int flags;

	enum http_auth_type auth_type;
	const char *auth_user;
	const char *auth_pass;
};

struct http_conn;

int http_request(const char *url, enum http_request req,
	void (*cb)(struct http_conn *, void *arg), void *cb_arg,
	struct http_request_data *data, struct http_request_opts *opts);

struct buffer_queue * http_conn_response_queue(struct http_conn *conn);

char *http_conn_response(struct http_conn *conn);

void *http_conn_response_raw(struct http_conn *conn, ssize_t *len);

int http_conn_response_code(struct http_conn *conn);

const char *http_conn_header_value(struct http_conn *conn, const char *key);

#endif

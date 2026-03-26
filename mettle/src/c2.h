/**
 * @brief c2 transport manager
 * @file c2.h
 */

#ifndef _C2_H_
#define _C2_H_

#include <ev.h>
#include "buffer_queue.h"

/*
 * C2 Profile configuration for GET/POST verbs
 */
struct c2_verb_config {
	char *uri;
	int enc;
	void *prefix;
	size_t prefix_len;
	void *suffix;
	size_t suffix_len;
	int prefix_skip;
	int suffix_skip;
	char *uuid_get;
	char *uuid_header;
	char *uuid_cookie;
};

/*
 * Per-transport configuration parsed from TLV config block
 */
struct c2_transport_config {
	uint32_t comm_timeout;
	uint32_t retry_total;
	uint32_t retry_wait;
	char *proxy_url;
	char *user_agent;
	char *custom_headers;
	void *cert_hash;
	size_t cert_hash_len;
	struct c2_verb_config *c2_get;
	struct c2_verb_config *c2_post;
};

void c2_verb_config_free(struct c2_verb_config *vc);
void c2_transport_config_free(struct c2_transport_config *tc);

/*
 * C2 Manager
 */
struct c2;

struct c2 * c2_new(struct ev_loop *loop);

int c2_add_transport_uri(struct c2 *c2, const char *uri);

int c2_add_transport_uri_config(struct c2 *c2, const char *uri,
	struct c2_transport_config *config);

int c2_start(struct c2 *c2);

int c2_close(struct c2 *c2);

void c2_free(struct c2 *c2);

#define C2_REACHABLE 0x01

typedef void (*c2_data_cb)(struct c2 *c2, void *arg);
typedef void (*c2_event_cb)(struct c2 *c2, int event, void *arg);

void c2_set_cbs(struct c2 *be,
	c2_data_cb read_cb,
	c2_data_cb write_cb,
	c2_event_cb event_cb,
	void *cb_arg);

ssize_t c2_read(struct c2 *c2, void *buf, size_t buflen);

ssize_t c2_write(struct c2 *c2, void *buf, size_t buflen);

struct buffer_queue* c2_ingress_queue(struct c2 *c2);

struct buffer_queue* c2_egress_queue(struct c2 *c2);

/*
 * Transport API
 */
struct c2_transport;

struct c2_transport_cbs {
	int (*init)(struct c2_transport *t);
	void (*start)(struct c2_transport *t);
	void (*egress)(struct c2_transport *t, struct buffer_queue *egress);
	void (*stop)(struct c2_transport *t);
	void (*free)(struct c2_transport *t);
};

int c2_register_transport_type(struct c2 *c2, const char *proto,
	struct c2_transport_cbs *cbs);

struct c2_transport* c2_get_current_transport(struct c2 *c2);

struct c2_transport_config * c2_transport_get_config(struct c2_transport *t);

const char * c2_transport_uri(struct c2_transport *t);
const char * c2_transport_dest(struct c2_transport *t);
struct ev_loop * c2_transport_loop(struct c2_transport *loop);

void * c2_transport_get_ctx(struct c2_transport *t);
void c2_transport_set_ctx(struct c2_transport *t, void *ctx);

void c2_transport_reachable(struct c2_transport *t);
void c2_transport_unreachable(struct c2_transport *t);

void c2_transport_ingress_buf(struct c2_transport *t, void *buf, size_t buflen);
void c2_transport_ingress_queue(struct c2_transport *t, struct buffer_queue *src);

#endif

/**
 * @brief c2 transport manager
 * @file c2.h
 */

#ifndef _C2_H_
#define _C2_H_

#include <ev.h>
#include "buffer_queue.h"

struct c2;

struct c2 * c2_new(struct ev_loop *loop);

int c2_add_transport_uri(struct c2 *c2, const char *uri);

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

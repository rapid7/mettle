/**
 * @brief c2 transport manager
 * @file c2.c
 */

#include <ev.h>
#include <eio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "c2.h"
#include "c2_transports.h"
#include "network_client.h"
#include "http_client.h"
#include "log.h"
#include "utlist.h"

struct c2_transport {
	struct c2_transport *prev, *next;
	char *uri, *dest;
	struct c2 *c2;
	struct c2_transport_type *type;
	void *ctx;
};

struct c2_transport_type {
	struct c2_transport_type *next;
	char *proto;
	struct c2_transport_cbs cbs;
};

struct c2 {
	struct ev_loop *loop;

	struct c2_transport_type *transport_types;
	struct c2_transport *transports;
	struct c2_transport *curr_transport;
	struct ev_timer transport_timer;
	enum {
		c2_transport_state_unknown,
		c2_transport_state_starting,
		c2_transport_state_reachable,
		c2_transport_state_unreachable
	} transport_state;

	struct buffer_queue *ingress;
	struct buffer_queue *egress;

	c2_data_cb read_cb;
	c2_data_cb write_cb;
	c2_event_cb event_cb;
	void *cb_arg;
};

int
c2_register_transport_type(struct c2 *c2, const char *proto,
		struct c2_transport_cbs *cbs)
{
	struct c2_transport_type *type = calloc(1, sizeof *type);
	if (type == NULL) {
		return -1;
	}

	type->proto = strdup(proto);
	if (type->proto == NULL) {
		free(type);
		return -1;
	}
	type->cbs = *cbs;

	LL_PREPEND(c2->transport_types, type);
	return 0;
}

static struct c2_transport_type *
c2_find_transport_type(struct c2 *c2, const char *proto)
{
	struct c2_transport_type *type;
	LL_FOREACH(c2->transport_types, type) {
		if (strncmp(proto, type->proto, strlen(type->proto)) == 0) {
			return type;
		}
	}
	return NULL;
}

static void
c2_remove_transport_types(struct c2 *c2)
{
	struct c2_transport_type *type, *tmp;
	LL_FOREACH_SAFE(c2->transport_types, type, tmp) {
		LL_DELETE(c2->transport_types, type);
		free(type->proto);
		free(type);
	}
}

static int
c2_remove_transports(struct c2 *c2)
{
	struct c2_transport *t, *tmp1, *tmp2;
	CDL_FOREACH_SAFE(c2->transports, t, tmp1, tmp2) {
		CDL_DELETE(c2->transports, t);
		if (t->type->cbs.free) {
			t->type->cbs.free(t);
		}
		free(t->uri);
		free(t);
	}
	return 0;
}

int c2_add_transport_uri(struct c2 *c2, const char *uri)
{
	struct c2_transport *t = NULL;
	struct c2_transport_type *type = c2_find_transport_type(c2, uri);
	if (type == NULL) {
		goto err;
	}

	t = calloc(1, sizeof *t);
	if (t == NULL) {
		goto err;
	}
	t->c2 = c2;
	t->type = type;
	t->uri = strdup(uri);
	if (t->uri == NULL) {
		goto err;
	}

	/*
	 * t->dest points to the string beyond the protocol specifier
	 */
	t->dest = strstr(t->uri, "://");
	if (t->dest == NULL || strlen(t->dest) < 4) {
		goto err;
	}
	t->dest += 3;

	if (t->type->cbs.init) {
		t->type->cbs.init(t);
	}

	CDL_APPEND(c2->transports, t);

	return 0;
err:
	if (t) {
		free(t->uri);
		free(t);
	}
	return -1;
}

static struct c2_transport *
choose_next_transport(struct c2 *c2)
{
	if (c2->curr_transport == NULL) {
		c2->curr_transport = c2->transports;
	} else {
		c2->curr_transport = c2->curr_transport->next;
	}
	return c2->curr_transport;
}

static void transport_tx(struct c2 *c2)
{
	struct c2_transport *t = c2->curr_transport;
	if (t->type->cbs.egress) {
		t->type->cbs.egress(t, t->c2->egress);
	}
}

ssize_t c2_read(struct c2 *c2, void *buf, size_t buflen)
{
	return buffer_queue_remove(c2->ingress, buf, buflen);
}

ssize_t c2_write(struct c2 *c2, void *buf, size_t buflen)
{
	ssize_t len = buffer_queue_add(c2->egress, buf, buflen) == 0 ? buflen : 0;
	if (len) {
		transport_tx(c2);
	}
	return len;
}

struct c2_transport* c2_get_current_transport(struct c2 *c2)
{
	return c2->curr_transport;
}

void c2_transport_ingress_buf(struct c2_transport *t, void *buf, size_t buflen)
{
	if (buffer_queue_add(t->c2->ingress, buf, buflen) == 0) {
		if (t->c2->read_cb) {
			t->c2->read_cb(t->c2, t->c2->cb_arg);
		}
	}
}

void c2_transport_ingress_queue(struct c2_transport *t, struct buffer_queue *src)
{
	if (buffer_queue_move_all(t->c2->ingress, src) > 0) {
		if (t->c2->read_cb) {
			t->c2->read_cb(t->c2, t->c2->cb_arg);
		}
	}
}

struct buffer_queue* c2_ingress_queue(struct c2 *c2)
{
	return c2->ingress;
}

struct buffer_queue* c2_egress_queue(struct c2 *c2)
{
	return c2->egress;
}

void c2_set_cbs(struct c2 *c2,
	c2_data_cb read_cb,
	c2_data_cb write_cb,
	c2_event_cb event_cb,
	void *cb_arg)
{
    c2->read_cb = read_cb;
    c2->write_cb = write_cb;
    c2->event_cb = event_cb;
    c2->cb_arg = cb_arg;
}

static void
transport_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct c2 *c2 = w->data;

	struct c2_transport *t = c2->curr_transport;
	if (c2->curr_transport == NULL) {
		t = choose_next_transport(c2);
	}

	if (t == NULL) {
		return;
	}

	if (c2->transport_state == c2_transport_state_unknown) {

		if (t->type->cbs.start) {
			t->type->cbs.start(t);
		}
		c2->transport_state = c2_transport_state_starting;

	} if (c2->transport_state == c2_transport_state_unreachable) {
		
		t = c2->curr_transport;    // old transport
		choose_next_transport(c2); // new transport

		// switch transport only if they are different
		if(t != c2->curr_transport) {
			if (t->type->cbs.stop) {
				t->type->cbs.stop(t);
			}
			t = c2->curr_transport;
			if (t->type->cbs.start) {
				t->type->cbs.start(t);
			}
			c2->transport_state = c2_transport_state_starting;
		}
	}
}

void
c2_transport_reachable(struct c2_transport *t)
{
	t->c2->transport_state = c2_transport_state_reachable;
	if (t->c2->event_cb) {
		t->c2->event_cb(t->c2, C2_REACHABLE, t->c2->cb_arg);
	}
}

void c2_transport_unreachable(struct c2_transport *t)
{
	t->c2->transport_state = c2_transport_state_unreachable;
}

const char * c2_transport_uri(struct c2_transport *t)
{
	return t->uri;
}

const char * c2_transport_dest(struct c2_transport *t)
{
	return t->dest;
}

struct ev_loop * c2_transport_loop(struct c2_transport *t)
{
	return t->c2->loop;
}

void * c2_transport_get_ctx(struct c2_transport *t)
{
	return t->ctx;
}

void c2_transport_set_ctx(struct c2_transport *t, void *ctx)
{
	t->ctx = ctx;
}

int c2_start(struct c2 *c2)
{
	ev_timer_start(c2->loop, &c2->transport_timer);
	return 0;
}

void c2_free(struct c2 *c2)
{
	if (c2) {
		ev_timer_stop(c2->loop, &c2->transport_timer);

		if (c2->ingress) {
			buffer_queue_free(c2->ingress);
			c2->ingress = NULL;
		}

		if (c2->egress) {
			buffer_queue_free(c2->egress);
			c2->egress = NULL;
		}

		c2_remove_transports(c2);
		c2_remove_transport_types(c2);
		free(c2);
	}
}

struct c2* c2_new(struct ev_loop *loop)
{
	struct c2 *c2 = calloc(1, sizeof(*c2));
	if (c2) {
		c2->loop = loop;
		c2->ingress = buffer_queue_new();
		if (c2->ingress == NULL) {
			goto err;
		}
		c2->egress = buffer_queue_new();
		if (c2->egress == NULL) {
			goto err;
		}

		ev_timer_init(&c2->transport_timer, transport_cb, 0, 1.0);
		c2->transport_timer.data = c2;

#ifndef LIBEXTENSION
		c2_register_http_transports(c2);
		c2_register_tcp_transports(c2);
#endif
	}
	return c2;
err:
	c2_free(c2);
	return NULL;
}

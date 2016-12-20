/**
 * Copyright 2016 Rapid7
 * @file bufferev.h
 */

#ifndef _BUFFEREV_H_
#define _BUFFEREV_H_

#include <ev.h>

#include "buffer_queue.h"

enum network_proto {
	network_proto_udp,
	network_proto_tcp,
	network_proto_tls,
};

const char *network_proto_to_str(enum network_proto proto);

enum network_proto network_str_to_proto(const char *proto);

struct bufferev;

struct bufferev * bufferev_new(struct ev_loop *loop);

int bufferev_connect_tcp_sock(struct bufferev *be, int sock);

int bufferev_connect_addrinfo(struct bufferev *be, struct addrinfo *ai,
	float timeout_s);

typedef void (*bufferev_cb_t)(struct bufferev *be, void *arg);

void bufferev_set_connect_cb(struct bufferev *be,
    bufferev_cb_t cb, void *arg);

void bufferev_set_read_cb(struct bufferev *be,
    bufferev_cb_t cb, void *arg);

void bufferev_set_error_cb(struct bufferev *be,
    bufferev_cb_t cb, void *arg);

void bufferev_set_close_cb(struct bufferev *be,
    bufferev_cb_t cb, void *arg);

struct buffer_queue * bufferev_rx_queue(struct bufferev *be);

size_t bufferev_peek(struct bufferev *be, void *buf, size_t buflen);

size_t bufferev_read(struct bufferev *be, void *buf, size_t buflen);

size_t bufferev_bytes_available(struct bufferev *be);

ssize_t bufferev_write(struct bufferev *be, void *buf, size_t buflen);

void bufferev_free(struct bufferev *be);

#endif

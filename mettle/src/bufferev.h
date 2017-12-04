/**
 * Copyright 2016 Rapid7
 * @file bufferev.h
 */

#ifndef _BUFFEREV_H_
#define _BUFFEREV_H_

#include <ev.h>
#include <netdb.h>
#include <sys/types.h>

#include "buffer_queue.h"

enum network_proto {
	network_proto_udp,
	network_proto_tcp,
	network_proto_tls,
};

struct bufferev;

struct bufferev * bufferev_new(struct ev_loop *loop);

int bufferev_connect_tcp_sock(struct bufferev *be, int sock);

int bufferev_connect_addrinfo(struct bufferev *be,
	struct addrinfo *src_addr, struct addrinfo *dst_addr, float timeout_s);

#define BEV_READING   0x01  // error encountered while reading
#define BEV_WRITING   0x02  // error encountered while writing
#define BEV_EOF       0x04  // end of file reached
#define BEV_ERROR     0x08  // unrecoverable error encountered
#define BEV_TIMEOUT   0x10  // user-specified timeout reached
#define BEV_CONNECTED 0x20  // connect operation finished

typedef void (*bufferev_data_cb)(struct bufferev *be, void *arg);
typedef void (*bufferev_event_cb)(struct bufferev *be, int event, void *arg);

void bufferev_set_cbs(struct bufferev *be,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg);

struct buffer_queue * bufferev_rx_queue(struct bufferev *be);

size_t bufferev_peek(struct bufferev *be, void *buf, size_t buflen);

size_t bufferev_read(struct bufferev *be, void *buf, size_t buflen);

struct buffer_queue *bufferev_read_queue(struct bufferev *be);

struct bufferev_udp_msg {
	socklen_t src_len;
	ssize_t buf_len;
	struct sockaddr_storage src;
	char buf[];
};

char * bufferev_get_udp_msg_peer_addr(struct bufferev_udp_msg *msg, uint16_t *port);

void *bufferev_read_msg(struct bufferev *be, size_t *len);

void *bufferev_peek_msg(struct bufferev *be, size_t *len);

size_t bufferev_bytes_available(struct bufferev *be);

ssize_t bufferev_write(struct bufferev *be, const void *buf, size_t buflen);

char * bufferev_get_local_addr(struct bufferev *be, uint16_t *port);

char * bufferev_get_peer_addr(struct bufferev *be, uint16_t *port);

void bufferev_free(struct bufferev *be);

#endif

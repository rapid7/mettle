/**
 * Copyright 2015 Rapid7
 * @brief Durable multi-transport client network connection
 * @file network_client.h
 */

#ifndef _NETWORK_CLIENT_H_
#define _NETWORK_CLIENT_H_

#include <uv.h>

#include "buffer_queue.h"

struct network_client;

struct network_client * network_client_new(uv_loop_t *loop);

int network_client_add_server(struct network_client *nc, const char *uri);

int network_client_start(struct network_client *nc);

typedef void (*network_client_cb_t)(struct network_client *nc, void *arg);

void network_client_set_read_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

void network_client_set_connect_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

void network_client_set_close_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

struct buffer_queue * network_client_rx_queue(struct network_client *nc);

size_t network_client_peek(struct network_client *nc, void *buf, size_t buflen);

size_t network_client_read(struct network_client *nc, void *buf, size_t buflen);

size_t network_client_bytes_available(struct network_client *nc);

int network_client_write(struct network_client *nc, void *buf, size_t buflen);

int network_client_close(struct network_client *nc);

void network_client_free(struct network_client *nc);

#endif

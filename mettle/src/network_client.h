/**
 * Copyright 2015 Rapid7
 * @brief Durable multi-transport client network connection
 * @file network_client.h
 */

#ifndef _NETWORK_CLIENT_H_
#define _NETWORK_CLIENT_H_

#include "bufferev.h"

struct network_client;

struct network_client * network_client_new(struct ev_loop *loop);

void network_client_set_src(struct network_client *nc, const char *addr, uint16_t port);

int network_client_add_uri(struct network_client *nc, const char *uri);

int network_client_add_tcp_sock(struct network_client *nc, int sock);

int network_client_start(struct network_client *nc);

void network_client_set_cbs(struct network_client *be,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg);

void network_client_set_retries(struct network_client *nc, int retries);

ssize_t network_client_read(struct network_client *nc, void *buf, size_t buflen);

void * network_client_read_msg(struct network_client *nc, size_t *buflen);

ssize_t network_client_write(struct network_client *nc, void *buf, size_t buflen);

int network_client_stop(struct network_client *nc);

void network_client_free(struct network_client *nc);

#endif

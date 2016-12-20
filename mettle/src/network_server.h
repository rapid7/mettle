/**
 * Copyright 2016 Rapid7
 * @file network_server.h
 */

#ifndef _NETWORK_SERVER_H_
#define _NETWORK_SERVER_H_

#include <ev.h>

#include "bufferev.h"

struct network_server;

struct network_server * network_server_new(struct ev_loop *loop,
		const char *host, uint16_t port,
		void (* connect_cb)(struct bufferev *be, void *arg),
		void (* read_cb)(struct bufferev *be, void *arg),
		void (* close_cb)(struct network_server *ne));

int network_server_start(struct network_server *ns);

void network_server_free(struct network_server *ns);

#endif

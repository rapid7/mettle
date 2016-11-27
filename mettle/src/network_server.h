/**
 * Copyright 2016 Rapid7
 * @file network_server.h
 */

#ifndef _NETWORK_SERVER_H_
#define _NETWORK_SERVER_H_

#include <ev.h>

#include "buffer_queue.h"

struct network_server;

struct network_server * network_server_new(struct ev_loop *loop);

int network_server_start(struct network_server *nc);

void network_server_free(struct network_server *nc);

#endif

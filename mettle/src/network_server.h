/**
 * Copyright 2016 Rapid7
 * @file network_server.h
 */

#ifndef _NETWORK_SERVER_H_
#define _NETWORK_SERVER_H_

#include <ev.h>

#include "bufferev.h"

struct network_server;

struct network_server * network_server_new(struct ev_loop *loop);

int network_server_listen_tcp(struct network_server *ns,
	const char *host, uint16_t port);

void network_server_setcbs(struct network_server *ns,
	bufferev_data_cb read_cb,
	bufferev_data_cb write_cb,
	bufferev_event_cb event_cb,
	void *cb_arg);

void network_server_free(struct network_server *ns);

char * network_server_get_local_addr(struct network_server *ns, uint16_t *port);

#endif

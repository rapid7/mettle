/**
 * @brief Durable multi-transport client network connection
 */

#ifndef _NETWORK_CLIENT_H_
#define _NETWORK_CLIENT_H_

#include <uv.h>

struct network_client;

struct network_client * network_client(uv_loop_t *loop);

int network_client_add_server(struct network_client *nc, const char *uri);

int network_client_start(struct network_client *nc);

typedef void (*network_client_cb_t)(struct network_client *nc, void *arg);

void network_client_set_read_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

void network_client_set_connect_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

void network_client_set_close_cb(struct network_client *nc,
		network_client_cb_t cb, void *arg);

int network_client_read(struct network_client *nc, void *buf, size_t buflen);

int network_client_write(struct network_client *nc, void *buf, size_t buflen);

int network_client_close(struct network_client *nc);

void network_client_free(struct network_client *nc);

#endif

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

void network_client_free(struct network_client *nc);

#endif

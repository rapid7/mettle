/**
 * @brief c2 transport initializers
 * @file c2_transports.h
 */

#ifndef _C2_TRANSPORTS_H_
#define _C2_TRANSPORTS_H_

void c2_register_http_transports(struct c2 *c2);

void c2_register_tcp_transports(struct c2 *c2);

int http_transport_egress_pending(struct c2_transport *t);

#endif

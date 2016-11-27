/**
 * Copyright 2016 Rapid7
 * @brief Network Channel API
 * @file channel.c
 */

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "network_server.h"
#include "tlv.h"
#include "util.h"

static struct tlv_packet *tcp_server_new(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

void net_server_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "stdapi_net_tcp_server", tcp_server_new, m);
}


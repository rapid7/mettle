/**
 * Copyright 2016 Rapid7
 * @brief Network Resolve API
 * @file resolve.c
 */

#include <unistd.h>

#include <dnet.h>
#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

static
void resolve_host_async(struct eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p = tlv_packet_response(ctx);
	int ret_val = TLV_RESULT_SUCCESS;

	uint32_t addr_type;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_ADDR_TYPE, &addr_type) ||
			(addr_type != AF_INET && addr_type != AF_INET6)) {
		log_info("Unsupported address family '%u' for hostname resolution", addr_type);
		ret_val = TLV_RESULT_EINVAL;
		goto done;
	}

	struct addrinfo hints = {
		.ai_family = addr_type,
	};

	struct tlv_iterator i = {
		.packet = ctx->req,
		.value_type = TLV_TYPE_HOST_NAME,
	};
	const char *hostname;
	while ((hostname = tlv_packet_iterate_str(&i))) {
		struct addrinfo *resolved_host = NULL;

		int result = getaddrinfo(hostname, NULL, &hints, &resolved_host);
		if (result == 0) {
			struct addr addr_host;

			if (addr_type == AF_INET) {
				addr_pack(&addr_host, ADDR_TYPE_IP, IP_ADDR_BITS, \
						&((struct sockaddr_in *)(resolved_host->ai_addr))->sin_addr, \
						IP_ADDR_LEN);
			} else {
				addr_pack(&addr_host, ADDR_TYPE_IP6, IP6_ADDR_BITS, \
						&((struct sockaddr_in6 *)(resolved_host->ai_addr))->sin6_addr, \
						IP6_ADDR_LEN);
			}
			p = tlv_packet_add_addr(p, TLV_TYPE_IP, 0, 0, &addr_host);
			p = tlv_packet_add_u32(p, TLV_TYPE_ADDR_TYPE, addr_type);

			// XXX: C meterpreter has comment about this free possibliy causing segfaults on Linux
			freeaddrinfo(resolved_host);
		} else {
			log_info("Unable to resolve host '%s': %d (%s)",
					hostname, result, gai_strerror(result));
			tlv_packet_add_raw(p, TLV_TYPE_IP, NULL, 0);
		}
	}
done:
	tlv_packet_add_result(p, ret_val);
	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}

static
struct tlv_packet *resolve_host_req(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	eio_custom(resolve_host_async, 0, NULL, ctx);
	return NULL;
}

struct tlv_packet *net_resolve_host(struct tlv_handler_ctx *ctx)
{
	return resolve_host_req(ctx);
}

struct tlv_packet *net_resolve_hosts(struct tlv_handler_ctx *ctx)
{
	return resolve_host_req(ctx);
}

void net_resolve_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_RESOLVE_HOST, net_resolve_host, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_RESOLVE_HOSTS, net_resolve_hosts, m);
}

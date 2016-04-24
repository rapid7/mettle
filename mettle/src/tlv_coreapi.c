/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "tlv.h"

#include <mettle.h>

static struct tlv_packet *machine_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_MACHINE_ID, mettle_get_fqdn(m));
}

static void add_method(const char *method, void *arg)
{
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_str(*p, TLV_TYPE_STRING, method);
}

static struct tlv_packet *enumextcmd(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	const char *extension = tlv_packet_get_str(ctx->req, TLV_TYPE_STRING);
	if (extension == NULL) {
		return NULL;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(td, extension, add_method, &p);
	return p;
}

static struct tlv_packet *core_shutdown(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

	void (*nada)(void) = NULL;
	nada();

	return p;
}

void tlv_register_coreapi(struct mettle *m, struct tlv_dispatcher *td)
{
	tlv_dispatcher_add_handler(td, "core_enumextcmd", enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", machine_id, m);
	tlv_dispatcher_add_handler(td, "core_shutdown", core_shutdown, m);
}

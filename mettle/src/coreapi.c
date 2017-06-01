/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "log.h"
#include "tlv.h"

#include <mettle.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>


static void add_method(const char *method, void *arg)
{
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_str(*p, TLV_TYPE_STRING, method);
}

static struct tlv_packet *enumextcmd(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	const char *extension = tlv_packet_get_str(ctx->req, TLV_TYPE_STRING);

	/*
	 * When enumerating stdapi, send everything we know about so far
	 */
	if (extension == NULL || strcmp(extension, "stdapi") == 0) {
		extension = NULL;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(td, extension, add_method, &p);
	return p;
}

static struct tlv_packet *core_shutdown(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

#ifdef SIGKILL
	/*
	 * First try to kill ourselves with a signal
	 */
	raise(SIGKILL);
#endif

	/*
	 * Try to simply exit
	 */
	exit(0);

	/*
	 * Finally, trigger a SIGSEGV
	 */
	void (*nada) (void) = NULL;
	nada();

	return p;
}

static struct tlv_packet *core_machine_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_fmt(p, TLV_TYPE_MACHINE_ID,
		"%s:%s", mettle_get_fqdn(m), mettle_get_machine_id(m));
}

static struct tlv_packet *core_set_uuid(struct tlv_handler_ctx *ctx)
{
	size_t uuid_len = 0;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	char *uuid = tlv_packet_get_raw(ctx->req, TLV_TYPE_UUID, &uuid_len);

	if (uuid && uuid_len) {
		tlv_dispatcher_set_uuid(td, uuid, uuid_len);
	}

	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

static struct tlv_packet *core_uuid(struct tlv_handler_ctx *ctx)
{
	size_t uuid_len;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	const char *uuid = tlv_dispatcher_get_uuid(td, &uuid_len);

	if (uuid && uuid_len) {
	       struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	       return tlv_packet_add_raw(p, TLV_TYPE_UUID, uuid, uuid_len);
	}

	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

static struct tlv_packet *core_loadlib(struct tlv_handler_ctx *ctx)
{
	const char *lib_path = tlv_packet_get_str(ctx->req, TLV_TYPE_LIBRARY_PATH);
	const char *target_path = tlv_packet_get_str(ctx->req, TLV_TYPE_TARGET_PATH);
	printf("library %s\n", lib_path);
	printf("target %s\n", target_path);

	uint32_t flags = 0;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_FLAGS, &flags) == -1) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	printf("flags %d\n", flags);

	void* handle = dlopen(lib_path, RTLD_LAZY);
	printf("loading %p\n", handle);
	if (handle != 0) {
		/*lib_func init_exploit = dlsym(libexploit, "init_exploit");*/
		/*if (init_exploit != 0) {*/
			/*init_exploit();*/
		/*}*/
	} else {
	}
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

void tlv_register_coreapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "core_enumextcmd", enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", core_machine_id, m);
	tlv_dispatcher_add_handler(td, "core_set_uuid", core_set_uuid, m);
	tlv_dispatcher_add_handler(td, "core_uuid", core_uuid, m);
	tlv_dispatcher_add_handler(td, "core_shutdown", core_shutdown, m);
	tlv_dispatcher_add_handler(td, "core_loadlib", core_loadlib, m);
}

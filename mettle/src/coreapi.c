/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "crypttlv.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "extensions.h"
#include "util-common.h"

#include <mettle.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static void add_command_id(uint32_t command_id, void *arg)
{
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_u32(*p, TLV_TYPE_UINT, command_id);
}

static struct tlv_packet *enumextcmd(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	uint32_t command_id_start = 0, command_id_end = 0;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_UINT, &command_id_start);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &command_id_end);
	command_id_end += command_id_start;

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(td, command_id_start, command_id_end, add_command_id, &p);
	return p;
}

static struct tlv_packet *core_shutdown(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	// We're done, allow main() to cleanup...
	struct mettle *m = ctx->arg;
	ev_break(mettle_get_loop(m), EVBREAK_ALL);

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

static struct tlv_packet *core_negotiate_tlv_encryption(struct tlv_handler_ctx *ctx)
{
#ifndef __MINGW32__
	size_t guid_len = 0;
	size_t pkey_len = 0;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	char *guid = tlv_packet_get_raw(ctx->req, TLV_TYPE_SESSION_GUID, &guid_len);
	unsigned char *pkey = tlv_packet_get_raw(ctx->req, TLV_TYPE_RSA_PUB_KEY, &pkey_len);

	if (pkey_len > 0) {
		struct tlv_encryption_ctx* enc_ctx = create_tlv_encryption_context(ENC_AES256);
		if (enc_ctx->key != NULL)
		{
			unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = { '\0' };
			int enc_len = 0;
			if ((enc_len = rsa_encrypt_pkcs(pkey, pkey_len, enc_ctx, buf)) > 0)
			{
				struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
				p = tlv_packet_add_u32(p, TLV_TYPE_SYM_KEY_TYPE, ENC_AES256);
				p = tlv_packet_add_raw(p, TLV_TYPE_ENC_SYM_KEY, buf, enc_len);
				tlv_dispatcher_add_encryption(td, enc_ctx);
				return p;
			}
		}
	}
#endif
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

static struct tlv_packet *core_loadlib(struct tlv_handler_ctx *ctx)
{
	uint32_t flags;
	size_t extension_len;
	struct mettle *m = ctx->arg;
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response(ctx);
	int fd = -1;
	int tlv_result = TLV_RESULT_FAILURE;
	const char *library_path = tlv_packet_get_str(ctx->req, TLV_TYPE_LIBRARY_PATH);
	const char *target_path = tlv_packet_get_str(ctx->req, TLV_TYPE_TARGET_PATH);
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

	/* Check if this is a binary image or executable. */
	const char bin_magic_number[] = BIN_MAGIC_NUMBER;
	if (strncmp((const char *)&extension[extension_len - sizeof(bin_magic_number)], bin_magic_number, sizeof(bin_magic_number)) == 0) {
		log_info("Loading extension '%s' from binary image", library_path);

		// Make a copy of this image, don't use the TLV buffer...
		unsigned char *extension_copy = malloc(extension_len);
		if (extension_copy == NULL) {
			log_error("Failed to allocate memory for '%s' binary image", library_path);
			goto done;
		}
		// TODO: free this mem when the extension no longer is running
		memcpy(extension_copy, extension, extension_len);
		if (extension_start_binary_image(m, library_path, extension, extension_len, NULL))
		{
			log_error("Failed to start extension from binary image '%s'", library_path);
			goto done;
		}
	} else {
		/* This is an executable that needs to be saved to the filesystem. */
		log_info("Loading extension '%s' from executable file", library_path);

		fd = open(target_path, O_CREAT|O_WRONLY, 0755);
		if(fd == -1) {
			log_error("Failed to open '%s': %s", target_path, strerror(errno));
			goto done;
		}

		int ret_val = write(fd, extension, extension_len);
		if (ret_val == -1) {
			log_error("Failed to write '%s': %s", target_path, strerror(errno));
			goto done;
		}
		if (ret_val != extension_len) {
			log_error("Failed to write the entire extension '%s' to disk", target_path);
			goto done;
		}
		close(fd);
		fd = -1;

		if (extension_start_executable(m, target_path, NULL))
		{
			log_error("Failed to start extension from file '%s'", target_path);
			goto done;
		}
	}


	tlv_result = TLV_RESULT_SUCCESS;

done:
	if (fd != -1) {
		close(fd);
	}
	p = tlv_packet_add_result(p, tlv_result);

	return p;
}

void tlv_register_coreapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_ENUMEXTCMD, enumextcmd, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_MACHINE_ID, core_machine_id, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_SET_UUID, core_set_uuid, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_GET_SESSION_GUID, core_get_session_guid, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_SET_SESSION_GUID, core_set_session_guid, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION, core_negotiate_tlv_encryption, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_LOADLIB, core_loadlib, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_SHUTDOWN, core_shutdown, m);
}

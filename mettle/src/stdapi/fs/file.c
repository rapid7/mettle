/**
 * Copyright 2015 Rapid7
 * @brief Filesystem API
 * @file file.c
 */

#include <stdlib.h>
#include <unistd.h>

#include <dnet.h>
#include <mettle.h>

#include "log.h"
#include "tlv.h"

static void fs_ls_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	uv_dirent_t dent;
	while (uv_fs_scandir_next(req, &dent) != UV_EOF) {
		p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, dent.name);
		p = tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, dent.name);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	free(req);
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx, void *arg)
{
	struct mettle *m = arg;
	uv_fs_t *req = NULL;
	int rc = TLV_RESULT_FAILURE;

	const char *path = tlv_packet_get_str(ctx->p, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL)
		goto err;

	req = calloc(1, sizeof(*req));
	if (req == NULL)
		goto err;

	req->data = ctx;
	if (uv_fs_scandir(mettle_get_loop(m), req, path, 0, fs_ls_cb) == -1)
		goto err;

	return NULL;

err:
	free(req);
	return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_stat(struct tlv_handler_ctx *ctx, void *arg)
{
	const char *path = tlv_packet_get_str(ctx->p, TLV_TYPE_FILE_PATH);
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *fs_getwd(struct tlv_handler_ctx *ctx, void *arg)
{
	char dir[PATH_MAX];
	if (getcwd(dir, sizeof(dir)) == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_DIRECTORY_PATH, dir);
}

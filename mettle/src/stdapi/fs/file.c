/**
 * Copyright 2015 Rapid7
 * @brief Filesystem API
 * @file file.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <dnet.h>
#include <mettle.h>

#include "log.h"
#include "tlv.h"

static uv_fs_t *get_fs_req(struct tlv_handler_ctx *ctx, struct mettle *m)
{
	uv_fs_t *req = calloc(1, sizeof(*req));
	if (req) {
		req->data = ctx;
	}
	return req;
}

static struct tlv_packet * add_stat(struct tlv_packet *p, uv_stat_t *us)
{
	struct meterp_stat {
		uint32_t dev;
		uint16_t ino;
		uint16_t mode;
		uint16_t nlink;
		uint16_t uid;
		uint16_t gid;
		uint16_t pad;
		uint32_t rdev;
		uint32_t size;
		uint64_t atime;
		uint64_t mtime;
		uint64_t ctime;
	} s = {
		.dev = us->st_dev,
		.ino = us->st_ino,
		.mode = us->st_mode,
		.nlink = us->st_nlink,
		.uid = us->st_uid,
		.gid = us->st_gid,
		.rdev = us->st_rdev,
		.size = us->st_size,
		.mtime = us->st_mtime,
		.atime = us->st_atime,
		.ctime = us->st_ctime
	};

	return tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, &s, sizeof(s));
}

static void fs_ls_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct mettle *m = ctx->arg;

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	uv_dirent_t dent;
	while (uv_fs_scandir_next(req, &dent) != UV_EOF) {
		p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, dent.name);
		p = tlv_packet_add_fmt(p, TLV_TYPE_FILE_PATH,
				"%s/%s", path, dent.name);

		uv_fs_t stat_req;
		if (uv_fs_stat(mettle_get_loop(m), &stat_req, path, NULL) == 0) {
			p = add_stat(p, &stat_req.statbuf);
		}
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	free(req);
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	int rc = TLV_RESULT_FAILURE;

	uv_fs_t *req = get_fs_req(ctx, m);
	if (req == NULL)
		goto err;

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL)
		goto err;

	if (uv_fs_scandir(mettle_get_loop(m), req, path, 0, fs_ls_cb) == -1)
		goto err;

	return NULL;

err:
	free(req);
	return tlv_packet_response_result(ctx, rc);
}

static void fs_stat_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	p = add_stat(p, &req->statbuf);
	tlv_dispatcher_enqueue_response(ctx->td, p);

	free(req);
}

struct tlv_packet *fs_stat(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	uv_fs_t *req = get_fs_req(ctx, m);
	int rc;

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		rc = TLV_RESULT_EINVAL;
		goto err;
	}

	if (uv_fs_stat(mettle_get_loop(m), req, path, fs_stat_cb) == -1) {
		rc = TLV_RESULT_ENOMEM;
		goto err;
	}

	return NULL;

err:
	free(req);
	return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *fs_getwd(struct tlv_handler_ctx *ctx)
{
	char dir[PATH_MAX];
	if (getcwd(dir, sizeof(dir)) == NULL) {
		return tlv_packet_response_result(ctx, errno);
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_DIRECTORY_PATH, dir);
}

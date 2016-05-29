/**
 * Copyright 2015 Rapid7
 * @brief Filesystem API
 * @file file.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <endian.h>

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
		.dev = htole32(us->st_dev),
		.ino = htole16(us->st_ino),
		.mode = htole16(us->st_mode),
		.nlink = htole16(us->st_nlink),
		.uid = htole16(us->st_uid),
		.gid = htole16(us->st_gid),
		.rdev = htole32(us->st_rdev),
		.size = htole32(us->st_size),
		.mtime = htole64(us->st_mtim.tv_sec),
		.atime = htole64(us->st_atim.tv_sec),
		.ctime = htole64(us->st_ctim.tv_sec),
	};

	return tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, &s, sizeof(s));
}

static void fs_ls_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct mettle *m = ctx->arg;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		uv_dirent_t dent;
		const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);

		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

		while (uv_fs_scandir_next(req, &dent) != UV_EOF) {
			char fq_path[PATH_MAX];
			snprintf(fq_path, sizeof(fq_path), "%s/%s", path, dent.name);
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, dent.name);
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, fq_path);

			uv_fs_t stat_req;
			if (uv_fs_stat(mettle_get_loop(m), &stat_req, fq_path, NULL) == 0) {
				p = add_stat(p, &stat_req.statbuf);
			}
		}
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	tlv_handler_ctx_free(ctx);
	free(req);
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	uv_fs_t *req = get_fs_req(ctx, m);
	if (req == NULL) {
		return tlv_packet_response_result(ctx, ENOMEM);
	}

	if (uv_fs_scandir(mettle_get_loop(m), req, path, 0, fs_ls_cb) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
}

static void fs_stat_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = add_stat(p, &req->statbuf);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	tlv_handler_ctx_free(ctx);
	free(req);
}

struct tlv_packet *fs_stat(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	uv_fs_t *req = get_fs_req(ctx, m);

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	if (uv_fs_stat(mettle_get_loop(m), req, path, fs_stat_cb) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
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


static void fs_mkdir_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	tlv_handler_ctx_free(ctx);
	free(req);
}

struct tlv_packet *fs_mkdir(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	struct mettle *m = ctx->arg;
	uv_fs_t *req = get_fs_req(ctx, m);

	if (uv_fs_mkdir(mettle_get_loop(m), req, path, 0777, fs_mkdir_cb) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
}

struct tlv_packet *fs_separator(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_STRING, "/");
}

struct tlv_packet *fs_expand_path(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, path);
}

static void fs_file_move_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	tlv_handler_ctx_free(ctx);
	free(req);
}

struct tlv_packet *fs_file_move(struct tlv_handler_ctx *ctx)
{
	const char *src = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_NAME);
	const char *dst = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);

	if (src == NULL || dst == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	struct mettle *m = ctx->arg;
	uv_fs_t *req = get_fs_req(ctx, m);
	if (req == NULL) {
		return tlv_packet_response_result(ctx, ENOMEM);
	}

	if (uv_fs_rename(mettle_get_loop(m), req, src, dst, fs_file_move_cb) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
}

static void fs_delete_file_cb(uv_fs_t *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);

	tlv_handler_ctx_free(ctx);
	free(req);
}

struct tlv_packet *fs_delete_file(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	struct mettle *m = ctx->arg;
	uv_fs_t *req = get_fs_req(ctx, m);
	if (req == NULL) {
		return tlv_packet_response_result(ctx, ENOMEM);
	}

	if (uv_fs_unlink(mettle_get_loop(m), req, path, fs_delete_file_cb) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
}

struct tlv_packet *fs_chdir(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	int rc = TLV_RESULT_SUCCESS;
	if (chdir(path) == -1) {
		rc = errno;
	}
	return tlv_packet_response_result(ctx, rc);
}

int file_new_cb(struct tlv_handler_ctx *ctx, struct channel *c)
{
	char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	char *mode = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_MODE);
	if (mode == NULL) {
		mode = "rb";
	}

	FILE *f = fopen(path, mode);
	if (!f) {
		return -1;
	}
	channel_set_ctx(c, f);
	return 0;
}

ssize_t file_read_cb(void *ctx, char *buf, size_t len)
{
	log_info("reading %zu bytes", len);
	return fread(buf, 1, len, ctx);
}

ssize_t file_write_cb(void *ctx, char *buf, size_t len)
{
	return fwrite(buf, 1, len, ctx);
}

bool file_eof_cb(void *ctx)
{
	log_info("eof? %u", feof(ctx));
	return feof(ctx);
}

int file_free_cb(void *ctx)
{
	return fclose(ctx);
}

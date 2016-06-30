/**
 * Copyright 2015 Rapid7
 * @brief Filesystem API
 * @file file.c
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include <dnet.h>
#include <eio.h>
#include <mettle.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"

#include "__fmodeflags.c"

#ifdef __APPLE__
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#define st_atim st_atimespec
#endif

static struct tlv_packet *
add_stat(struct tlv_packet *p, EIO_STRUCT_STAT *s)
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
	} ms = {
		.dev = htole32(s->st_dev),
		.ino = htole16(s->st_ino),
		.mode = htole16(s->st_mode),
		.nlink = htole16(s->st_nlink),
		.uid = htole16(s->st_uid),
		.gid = htole16(s->st_gid),
		.rdev = htole32(s->st_rdev),
		.size = htole32(s->st_size),
		.mtime = htole64(s->st_mtim.tv_sec),
		.atime = htole64(s->st_atim.tv_sec),
		.ctime = htole64(s->st_ctim.tv_sec),
	};

	return tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, &ms, sizeof(ms));
}

static int
fs_ls_cb(eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct mettle *m = ctx->arg;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		struct eio_dirent *ents = (struct eio_dirent *)req->ptr1;
		char *names = (char *)req->ptr2;

		for (int i = 0; i < req->result; ++i) {
			struct eio_dirent *ent = ents + i;
			char *name = names + ent->nameofs;

			char fq_path[PATH_MAX];
			snprintf(fq_path, sizeof(fq_path), "%s/%s", path, name);
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, name);
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, fq_path);
			struct stat buf;
			if (stat(fq_path, &buf) == 0) {
				p = add_stat(p, &buf);
			}
		}
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
	return 0;
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;

	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	if (eio_readdir(path, EIO_READDIR_DENTS, 0, fs_ls_cb, ctx) == NULL) {
		return tlv_packet_response_result(ctx, errno);
	}

	return NULL;
}

static int
fs_stat_cb(eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;

	if (req->result < 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = add_stat(p, (EIO_STRUCT_STAT *)req->ptr2);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);

	return 0;
}

struct tlv_packet *
fs_stat(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	eio_stat(path, 0, fs_stat_cb, ctx);
	return NULL;
}

struct tlv_packet *
fs_getwd(struct tlv_handler_ctx *ctx)
{
	char dir[PATH_MAX];
	if (getcwd(dir, sizeof(dir)) == NULL) {
		return tlv_packet_response_result(ctx, errno);
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_DIRECTORY_PATH, dir);
}

static int
fs_cb(eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p = tlv_packet_response_result(ctx,
		req->result < 0 ? TLV_RESULT_FAILURE : TLV_RESULT_SUCCESS);

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
	return 0;
}

struct tlv_packet *
fs_mkdir(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	struct mettle *m = ctx->arg;
	eio_mkdir(path, 0777, 0, fs_cb, ctx);
	return NULL;
}

struct tlv_packet *
fs_rmdir(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	struct mettle *m = ctx->arg;
	eio_rmdir(path, 0, fs_cb, ctx);
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

struct tlv_packet *fs_file_move(struct tlv_handler_ctx *ctx)
{
	const char *src = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_NAME);
	const char *dst = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);

	if (src == NULL || dst == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	struct mettle *m = ctx->arg;
	eio_rename(src, dst, 0, fs_cb, ctx);
	return NULL;
}

struct tlv_packet *fs_delete_file(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	struct mettle *m = ctx->arg;
	eio_unlink(path, 0, fs_cb, ctx);
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

static void
fs_md5_async(struct eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	int rc = 0;
	unsigned char digest[16] = {0};
	if (path == NULL) {
		rc = EINVAL;
		goto out;
	}

	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		rc = errno;
		goto out;
	}

	mbedtls_md5_context md5;
	mbedtls_md5_init(&md5);
	mbedtls_md5_starts(&md5);
	unsigned char buf[8096];
	size_t buf_len = 0;
	while ((buf_len = fread(buf, 1, sizeof(buf), f)) > 0) {
		mbedtls_md5_update(&md5, buf, buf_len);
	}
	mbedtls_md5_finish(&md5, digest);
	mbedtls_md5_free(&md5);

	fclose(f);

out:
	p = tlv_packet_response_result(ctx, rc);
	if (rc == 0) {
		p = tlv_packet_add_raw(p, TLV_TYPE_FILE_HASH, digest, sizeof(digest));
	}
	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}

struct tlv_packet *fs_md5(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	eio_custom(fs_md5_async, 0, NULL, ctx);
	return NULL;
}

static void
fs_sha1_async(struct eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	int rc = 0;
	unsigned char digest[20] = {0};
	if (path == NULL) {
		rc = EINVAL;
		goto out;
	}

	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		rc = errno;
		goto out;
	}

	mbedtls_sha1_context sha1;
	mbedtls_sha1_init(&sha1);
	mbedtls_sha1_starts(&sha1);
	unsigned char buf[8096];
	size_t buf_len = 0;
	while ((buf_len = fread(buf, 1, sizeof(buf), f)) > 0) {
		mbedtls_sha1_update(&sha1, buf, buf_len);
	}
	mbedtls_sha1_finish(&sha1, digest);
	mbedtls_sha1_free(&sha1);

	fclose(f);

out:
	p = tlv_packet_response_result(ctx, rc);
	if (rc == 0) {
		p = tlv_packet_add_raw(p, TLV_TYPE_FILE_HASH, digest, sizeof(digest));
	}
	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}

struct tlv_packet *fs_sha1(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	eio_custom(fs_sha1_async, 0, NULL, ctx);
	return NULL;
}

int file_new(struct tlv_handler_ctx *ctx, struct channel *c)
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

ssize_t file_read(void *ctx, char *buf, size_t len)
{
	return fread(buf, 1, len, ctx);
}

ssize_t file_write(void *ctx, char *buf, size_t len)
{
	return fwrite(buf, 1, len, ctx);
}

int file_seek(void *ctx, ssize_t offset, int whence)
{
	return fseek(ctx, offset, whence);
}

ssize_t file_tell(void *ctx)
{
	return ftell(ctx);
}

bool file_eof(void *ctx)
{
	return feof(ctx);
}

int file_free(void *ctx)
{
	return fclose(ctx);
}

void file_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	tlv_dispatcher_add_handler(td, "stdapi_fs_chdir", fs_chdir, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_delete_file", fs_delete_file, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_expand_path", fs_expand_path, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_file_move", fs_file_move, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_getwd", fs_getwd, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_mkdir", fs_mkdir, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_delete_dir", fs_rmdir, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_ls", fs_ls, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_separator", fs_separator, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_stat", fs_stat, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_md5", fs_md5, m);
	tlv_dispatcher_add_handler(td, "stdapi_fs_sha1", fs_sha1, m);

	struct channel_callbacks cbs = {
		.new_cb = file_new,
		.read_cb = file_read,
		.write_cb = file_write,
		.eof_cb = file_eof,
		.seek_cb = file_seek,
		.free_cb = file_free,
	};
	channelmgr_add_channel_type(cm, "stdapi_fs_file", &cbs);
}

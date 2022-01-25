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
#include <md5.h>
#include <sha1.h>

#include <libgen.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "eio_rmtree.h"

#ifdef __APPLE__
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#define st_atim st_atimespec
#endif

#define FS_SEARCH_NO_DATE UINT32_MAX

#ifdef __MINGW32__
#if !defined(S_ISLNK)
#define	S_ISLNK(mode) (0)
#endif
#endif

struct search_entry
{
	char *dir_path;
	struct search_entry *next;
	struct search_entry *prev;
};

static struct tlv_packet *
add_stat(struct tlv_packet *p, EIO_STRUCT_STAT *s)
{
	struct meterp_stat {
		uint32_t dev;
		uint32_t mode;
		uint32_t nlink;
		uint32_t uid;
		uint32_t gid;
		uint32_t rdev;
		uint64_t ino;
		uint64_t size;
		uint64_t atime;
		uint64_t mtime;
		uint64_t ctime;
	} __attribute__((__packed__)) ms = {
		.dev = htole32(s->st_dev),
		.mode = htole32(s->st_mode),
		.nlink = htole32(s->st_nlink),
		.uid = htole32(s->st_uid),
		.gid = htole32(s->st_gid),
		.rdev = htole32(s->st_rdev),
		.ino = htole64(s->st_ino),
		.size = htole64(s->st_size),
#ifndef _WIN32
		.mtime = htole64(s->st_mtim.tv_sec),
		.atime = htole64(s->st_atim.tv_sec),
		.ctime = htole64(s->st_ctim.tv_sec),
#endif
	};

	return tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, &ms, sizeof(ms));
}

#ifdef HAVE_GLOB

#include <glob.h>

static void
fs_ls_glob(eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;
	char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif
	glob_t glob_result;
	memset(&glob_result, 0, sizeof(glob_result));
	int glob_ret = glob(path, GLOB_TILDE, NULL, &glob_result);
	if (glob_ret != 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		for(size_t i = 0; i < glob_result.gl_pathc; ++i) {
			char *name = glob_result.gl_pathv[i];
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_PATH, name);
			struct stat buf;
			if (stat(name, &buf) == 0) {
				p = add_stat(p, &buf);
			}
			p = tlv_packet_add_str(p, TLV_TYPE_FILE_NAME, basename(name));
		}
	}

	globfree(&glob_result);

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}
#endif

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
#ifdef _WIN32
			p = tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, "", 0);
#else
			struct stat buf;
			if (stat(fq_path, &buf) == 0) {

				p = add_stat(p, &buf);
			} else {
				p = tlv_packet_add_raw(p, TLV_TYPE_STAT_BUF, "", 0);
			}
#endif
		}
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
	return 0;
}

struct tlv_packet *fs_ls(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

#ifdef HAVE_GLOB
	if (strchr(path, '*') != NULL) {
		eio_custom(fs_ls_glob, 0, NULL, ctx);
	} else
#endif
		if (eio_readdir(path, EIO_READDIR_DENTS, 0, fs_ls_cb, ctx) == NULL) {
			return tlv_packet_response_result(ctx, errno);
		}

	return NULL;
}

static void
search_add_result(struct tlv_handler_ctx *ctx, struct tlv_packet **p, char *sub_root, char *f_name, off_t f_size, off_t m_time)
{
	struct tlv_packet *res = NULL;

	if(!*p)
	{
		*p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}

	res = tlv_packet_new(TLV_TYPE_SEARCH_RESULTS, 0);
	res = tlv_packet_add_str(res, TLV_TYPE_FILE_PATH, sub_root);
	res = tlv_packet_add_str(res, TLV_TYPE_FILE_NAME, f_name);
	res = tlv_packet_add_u32(res, TLV_TYPE_FILE_SIZE, f_size);
	res = tlv_packet_add_u32(res, TLV_TYPE_SEARCH_MTIME, m_time);
	*p = tlv_packet_add_child(*p, res);
}

#ifdef HAVE_GLOB
static int
search_glob(struct tlv_handler_ctx *ctx, struct tlv_packet **p, char *sub_root, char *f_name, uint32_t start_date, uint32_t end_date)
{
	glob_t glob_results;
	struct stat s_buf;
	char glob_path[PATH_MAX + 1];

	if(snprintf(glob_path, PATH_MAX + 1, "%s/%s", sub_root, f_name) < 0)
	{
		return -1;
	}

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

#ifndef GLOB_PERIOD
#define GLOB_PERIOD 0
#endif

	memset(&glob_results, 0, sizeof(glob_t));
	memset(&s_buf, 0, sizeof(struct stat));
	if(glob(glob_path, GLOB_TILDE | GLOB_PERIOD, NULL, &glob_results) != 0)
	{
		globfree(&glob_results);
		return -1;
	}

	for(size_t i = 0; i < glob_results.gl_pathc; i++)
	{
#ifdef _WIN32
		if(stat(glob_results.gl_pathv[i], &s_buf) == 0)
		{
			uint32_t fmtime = s_buf.st_mtime;
#else
		if(lstat(glob_results.gl_pathv[i], &s_buf) == 0)
		{
			uint32_t fmtime = s_buf.st_mtim.tv_sec;
#endif

			if((start_date != FS_SEARCH_NO_DATE) && (start_date > fmtime))
			{
				continue;
			}
			if((end_date != FS_SEARCH_NO_DATE) && (end_date < fmtime))
			{
				continue;
			}
			search_add_result(ctx, p, sub_root, basename(glob_results.gl_pathv[i]), s_buf.st_size, fmtime);
		}
	}

	globfree(&glob_results);
	return 0;
}
#endif

static void
fs_search_cb(eio_req *req)
{
	bool recurse;
	bool perform_glob = false;
	uint32_t start_date;
	uint32_t end_date;
	int rc = TLV_RESULT_SUCCESS;
	struct tlv_packet *p = NULL;
	struct tlv_handler_ctx *ctx = req->data;
	char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_SEARCH_GLOB);
	char *search_root = tlv_packet_get_str(ctx->req, TLV_TYPE_SEARCH_ROOT);

	DIR *dir_str;
	struct dirent *f_entry;
	struct search_entry *curr_entry;

	tlv_packet_get_bool(ctx->req, TLV_TYPE_SEARCH_RECURSE, &recurse);

	if(tlv_packet_get_u32(ctx->req,TLV_TYPE_SEARCH_M_START_DATE, &start_date))
	{
		start_date = FS_SEARCH_NO_DATE;
	}
	if(tlv_packet_get_u32(ctx->req,TLV_TYPE_SEARCH_M_END_DATE, &end_date))
	{
		end_date = FS_SEARCH_NO_DATE;
	}
	if(search_root == NULL || (strcmp(search_root, "") == 0))
	{
		search_root = "/";
	}

	if(strchr(path, '*') != NULL)
	{
		perform_glob = true;
	}

	if((curr_entry = malloc(sizeof(struct search_entry))) == NULL)
	{
		rc = TLV_RESULT_ENOMEM;
		goto out;
	}

	int s_root_len = strlen(search_root);
	if(s_root_len > PATH_MAX)
	{
		rc = TLV_RESULT_FAILURE;
		goto out;
	}

	curr_entry->dir_path = malloc(s_root_len + 1);
	if(!curr_entry->dir_path)
	{
		free(curr_entry);
		rc = TLV_RESULT_ENOMEM;
		goto out;
	}

	memcpy(curr_entry->dir_path, search_root, s_root_len);
	curr_entry->dir_path[s_root_len] = '\0';
	curr_entry->next = NULL;
	curr_entry->prev = NULL;

	struct search_entry *tail = curr_entry;
	if((dir_str = opendir(search_root)) == NULL)
	{
		rc = EACCES;
		goto out;
	}

	while(curr_entry != NULL && dir_str != NULL)
	{
		f_entry = readdir(dir_str);
		if(f_entry == NULL && curr_entry->next == NULL) // nothing left to search
		{
			closedir(dir_str);
#ifdef HAVE_GLOB
			if(perform_glob)
			{
				search_glob(ctx, &p, curr_entry->dir_path, path, start_date, end_date);
			}
#endif

			free(curr_entry->dir_path);
			free(curr_entry);
			break;
		}
		else if(f_entry == NULL) // finished looking at files in current directory
		{
			closedir(dir_str);

#ifdef HAVE_GLOB
			if(perform_glob)
			{
				search_glob(ctx, &p, curr_entry->dir_path, path, start_date, end_date);
			}
#endif

			curr_entry = curr_entry->next;
			free(curr_entry->prev->dir_path);
			free(curr_entry->prev);

			/*
			 * ensure that the next dir to search can be opened
			 * and that the ones that can't be opened are disposed of
			 */
			while((dir_str = opendir(curr_entry->dir_path)) == NULL)
			{
				if(!curr_entry->next)
				{
					free(curr_entry->dir_path);
					free(curr_entry);
					break;
				}

				curr_entry = curr_entry->next;
				free(curr_entry->prev->dir_path);
				free(curr_entry->prev);
			}

			continue;
		}
		else if(strcmp(f_entry->d_name, ".") == 0 || strcmp(f_entry->d_name, "..") == 0)
		{
			continue;
		}

		struct stat f_info;
		char full_path[PATH_MAX + 1];
		if(strcmp(curr_entry->dir_path, "/") == 0)
		{
			snprintf(full_path, PATH_MAX + 1, "%s%s", curr_entry->dir_path, f_entry->d_name);
		}
		else
		{
			snprintf(full_path, PATH_MAX + 1, "%s/%s", curr_entry->dir_path, f_entry->d_name);
		}

#ifdef _WIN32
		if(stat(full_path, &f_info) != 0)
#else
		if(lstat(full_path, &f_info) != 0)
#endif
		{
			continue;
		}

		/*
		 * Add dir to check later
		 */
		if(S_ISDIR(f_info.st_mode) && recurse)
		{
			int path_len = sizeof(full_path);
			tail->next = malloc(sizeof(struct search_entry));
			if(tail->next)
			{
				tail->next->prev = tail;
				tail = tail->next;
				tail->dir_path = malloc(path_len + 1);
				if(tail->dir_path)
				{
					memcpy(tail->dir_path, full_path, path_len);
					tail->next = NULL;
				}
				else
				{
					tail = tail->prev;
					free(tail->next);
				}
			}
			continue;
		}

		/* no need to check literal entry names at this point */
		if(perform_glob)
		{
			continue;
		}

		if(strcmp(f_entry->d_name, path) == 0)
		{
#ifdef _WIN32
			uint32_t fmtime = f_info.st_mtime;
#else
			uint32_t fmtime = f_info.st_mtim.tv_sec;
#endif
			if((start_date != FS_SEARCH_NO_DATE) && (start_date > fmtime))
			{
				continue;
			}
			if((end_date != FS_SEARCH_NO_DATE) && (end_date < fmtime))
			{
				continue;
			}
			search_add_result(ctx, &p, curr_entry->dir_path, f_entry->d_name, f_info.st_size, fmtime);
		}
	}

out:
	if(!p)
	{
		p = tlv_packet_response_result(ctx, rc);
	}

	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}

struct tlv_packet *fs_search(struct tlv_handler_ctx *ctx)
{
	char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_SEARCH_GLOB);

	if(path == NULL)
	{
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}
#ifndef HAVE_GLOB
	if(strchr(path, '*') != NULL)
	{
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
#endif

	eio_custom(fs_search_cb, 0, NULL, ctx);

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

	eio_mkdir(path, 0777, 0, fs_cb, ctx);
	return NULL;
}

static int
fs_rmdir_cb(eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	const char *path = EIO_PATH(req);
	EIO_STRUCT_STAT *buf = (EIO_STRUCT_STAT *)req->ptr2;
	eio_req *new_req = NULL;

	if (req->result < 0) {
		return fs_cb(req);
	}

	if (S_ISLNK(buf->st_mode)) {
		new_req = eio_unlink(path, 0, fs_cb, ctx);
	} else if (S_ISDIR(buf->st_mode)) {
		new_req = eio_rmtree(path, 0, fs_cb, ctx);
	}

	if (!new_req) {
		req->result = -1;
		fs_cb(req);
	}

	return req->result;
}

struct tlv_packet *
fs_rmdir(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_DIRECTORY_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	eio_lstat(path, 0, fs_rmdir_cb, ctx);
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

	eio_rename(src, dst, 0, fs_cb, ctx);
	return NULL;
}

static void
fs_file_copy_async(struct eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	struct tlv_packet *p;
	int rc = TLV_RESULT_SUCCESS;
	const char *src = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_NAME);
	const char *dst = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);

	if (src == NULL || dst == NULL) {
		rc = EINVAL;
		goto out;
	}

	FILE* f1 = fopen(src, "rb");
	if (f1 == NULL) {
		rc = EINVAL;
		goto out;
	}

	FILE* f2 = fopen(dst, "wb");
	if (f2 == NULL) {
		fclose(f1);
		rc = EINVAL;
		goto out;
	}

	char buffer[4096];
	size_t n;
	while ((n = fread(buffer, sizeof(char), sizeof(buffer), f1)) > 0)
	{
		if (fwrite(buffer, sizeof(char), n, f2) != n) {
			fclose(f1);
			fclose(f2);
			rc = EINVAL;
			goto out;
		}
	}

	fclose(f1);
	fclose(f2);

out:
	p = tlv_packet_response_result(ctx, rc);
	tlv_dispatcher_enqueue_response(ctx->td, p);
	tlv_handler_ctx_free(ctx);
}

struct tlv_packet *fs_file_copy(struct tlv_handler_ctx *ctx)
{
	eio_custom(fs_file_copy_async, 0, NULL, ctx);
	return NULL;
}

struct tlv_packet *fs_chmod(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}
	uint32_t mode;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_FILE_MODE_T, &mode)) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

	eio_chmod(path, mode, 0, fs_cb, ctx);
	return NULL;
}

struct tlv_packet *fs_delete_file(struct tlv_handler_ctx *ctx)
{
	const char *path = tlv_packet_get_str(ctx->req, TLV_TYPE_FILE_PATH);
	if (path == NULL) {
		return tlv_packet_response_result(ctx, EINVAL);
	}

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

	MD5_CTX md5;
	MD5Init(&md5);
	unsigned char buf[8096];
	size_t buf_len = 0;
	while ((buf_len = fread(buf, 1, sizeof(buf), f)) > 0) {
		MD5Update(&md5, buf, buf_len);
	}
	MD5Final(digest, &md5);

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

	SHA1_CTX sha1;
	SHA1Init(&sha1);
	unsigned char buf[8096];
	size_t buf_len = 0;
	while ((buf_len = fread(buf, 1, sizeof(buf), f)) > 0) {
		SHA1Update(&sha1, buf, buf_len);
	}
	SHA1Final(digest, &sha1);

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

ssize_t file_read(struct channel *c, void *buf, size_t len)
{
	FILE *f = channel_get_ctx(c);
	return fread(buf, 1, len, f);
}

ssize_t file_write(struct channel *c, void *buf, size_t len)
{
	FILE *f = channel_get_ctx(c);
	return fwrite(buf, 1, len, f);
}

int file_seek(struct channel *c, ssize_t offset, int whence)
{
	FILE *f = channel_get_ctx(c);
	return fseek(f, offset, whence);
}

ssize_t file_tell(struct channel *c)
{
	FILE *f = channel_get_ctx(c);
	return ftell(f);
}

bool file_eof(struct channel *c)
{
	FILE *f = channel_get_ctx(c);
	return feof(f);
}

int file_free(struct channel *c)
{
	FILE *f = channel_get_ctx(c);
	return fclose(f);
}

void file_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct channelmgr *cm = mettle_get_channelmgr(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_CHDIR, fs_chdir, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_DELETE_FILE, fs_delete_file, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_FILE_EXPAND_PATH, fs_expand_path, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_FILE_MOVE, fs_file_move, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_FILE_COPY, fs_file_copy, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_CHMOD, fs_chmod, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_GETWD, fs_getwd, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_MKDIR, fs_mkdir, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_DELETE_DIR, fs_rmdir, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_LS, fs_ls, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_SEARCH, fs_search, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_SEPARATOR, fs_separator, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_STAT, fs_stat, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_MD5, fs_md5, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_FS_SHA1, fs_sha1, m);

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

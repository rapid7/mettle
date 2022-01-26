#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "eio_rmtree.h"

struct rmtree_ctx {
	char path[PATH_MAX];
	eio_req* grp_dents;
	eio_req* grp_dir;
	eio_cb cb;
	void *cb_data;
} rmtree_ctx;

static int
_grp_add(eio_req *grp, eio_req *req) {
	if (!req) {
		grp->result = -1;
		return -1;
	}

	eio_grp_add(grp, req);
	return 0;
}

static int
set_dents_cb(eio_req *req)
{
	struct rmtree_ctx *ctx = req->data;

	if (req->result < 0) {
		ctx->grp_dents->result = req->result;
	}

	return req->result;
}

static int
set_dir_cb(eio_req *req)
{
	struct rmtree_ctx *ctx = req->data;

	if (req->result < 0) {
		ctx->grp_dir->result = req->result;
	}

	return req->result;
}

static int
eio_rmtree_lstat_cb(eio_req *req)
{
	struct rmtree_ctx *ctx = req->data;
	const char *path = EIO_PATH(req);
	EIO_STRUCT_STAT *buf = (EIO_STRUCT_STAT *)req->ptr2;
	eio_req *new_req;

	if (set_dents_cb(req) < 0) {
		return req->result;
	}

	if (S_ISDIR(buf->st_mode)) {
		new_req = eio_rmtree(path, 0, set_dents_cb, ctx);
	} else {
		new_req = eio_unlink(path, 0, set_dents_cb, ctx);
	}
	return _grp_add(ctx->grp_dents, new_req);
}

static int
eio_rmtree_readdir_cb(eio_req *req)
{
	struct rmtree_ctx* ctx = req->data;
	const char *path = ctx->path;;
	char *name = (char *)req->ptr2;

	if (set_dents_cb(req) < 0) {
		return req->result;
	}

	for (int i = 0; i < req->result; ++i) {
		int error;

		char fq_path[PATH_MAX + 1];
		snprintf(fq_path, sizeof(fq_path), "%s/%s", path, name);
		error = _grp_add(ctx->grp_dents, eio_lstat(fq_path, 0, eio_rmtree_lstat_cb, ctx));
		if (error) {
			return error;
		}

		name += strlen(name) + 1;
	}
	return 0;
}

static int
eio_rmtree_cb_dents(eio_req *req)
{
	struct rmtree_ctx* ctx = req->data;

	if (set_dir_cb(req) < 0) {
		return req->result;
	}

	return _grp_add(ctx->grp_dir, eio_rmdir(ctx->path, 0, set_dir_cb, ctx));
}


static int
eio_rmtree_cb_dir(eio_req *req)
{
	struct rmtree_ctx* ctx = req->data;
	eio_cb cb = ctx->cb;
	req->data = ctx->cb_data;

	free(ctx);
	if (!cb) {
		return req->result;
	}
	return cb(req);
}

/*
 * Recursively delete a directory. Sub entries that are links to other directories are not followed.
 *
 * This uses a composite request, see the section "Creating Composite Requests". Each invocation uses two groups, one
 * to track the deletion of the subelements, and one to track the deletion of the directory itself.
 * http://pod.tst.eu/http://cvs.schmorp.de/libeio/eio.pod
 */
eio_req *
eio_rmtree(const char *path, int pri, eio_cb cb, void *data)
{
	struct rmtree_ctx* ctx = malloc(sizeof(rmtree_ctx));
	if (!ctx) {
		return NULL;
	}
	strncpy(ctx->path, path, PATH_MAX);
	ctx->cb = cb;
	ctx->cb_data = data;

	ctx->grp_dents = eio_grp(eio_rmtree_cb_dents, ctx);
	ctx->grp_dir = eio_grp(eio_rmtree_cb_dir, ctx);
	if (!(ctx->grp_dents && ctx->grp_dir)) {
		free(ctx);
		return NULL;
	}
	if (path == NULL) {
		ctx->grp_dents->result = -1;
		ctx->grp_dir->result = -1;
	} else {
		_grp_add(ctx->grp_dents, eio_readdir(path, EIO_READDIR_STAT_ORDER, pri, eio_rmtree_readdir_cb, ctx));
		eio_grp_add(ctx->grp_dir, ctx->grp_dents);
	}
	return ctx->grp_dir;
}

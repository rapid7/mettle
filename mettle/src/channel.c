#include <errno.h>

#include "channel.h"
#include "eio.h"
#include "log.h"
#include "mettle.h"
#include "tlv.h"
#include "command_ids.h"
#include "uthash.h"

struct channel {
	uint32_t id;
	UT_hash_handle hh;
	struct channel_type *type;
	struct channelmgr *cm;
	void *ctx;
	struct buffer_queue *queue;
	bool interactive;
	bool eof;
	bool shutting_down;
	bool started;
};

struct channel_type {
	char *name;
	UT_hash_handle hh;
	struct channel_callbacks cbs;
};

struct channelmgr {
	struct tlv_dispatcher *td;
	struct channel *channels;
	struct channel_type *types;
	uint32_t next_channel_id;
};

struct channelmgr * channelmgr_new(struct tlv_dispatcher *td)
{
	struct channelmgr *cm = calloc(1, sizeof(*cm));
	if (cm) {
		cm->next_channel_id = 1;
		cm->td = td;
	}
	return cm;
}

void channelmgr_free(struct channelmgr *cm)
{
	struct channel *c, *tmp;
	HASH_ITER(hh, cm->channels, c, tmp) {
		HASH_DEL(cm->channels, c);
		free(c);
	}
	free(cm);
}

struct channel * channelmgr_channel_new(struct channelmgr *cm, char *channel_type)
{
	struct channel_type *ct = channelmgr_type_by_name(cm, channel_type);
	if (ct == NULL) {
		log_info("could not find handlers for channel type %s", channel_type);
		return NULL;
	}

	struct channel *c = calloc(1, sizeof(*c));
	if (c) {
		c->id = cm->next_channel_id++;
		c->type = ct;
		c->cm = cm;
		c->queue = buffer_queue_new();
		if (c->queue == NULL) {
			free(c);
			c = NULL;
		} else {
			HASH_ADD_INT(cm->channels, id, c);
		}
	}
	return c;
}

void channel_free(struct channel *c)
{
	HASH_DEL(c->cm->channels, c);
	buffer_queue_free(c->queue);
	free(c);
}

struct channel *channelmgr_channel_by_id(struct channelmgr *cm, uint32_t id)
{
	struct channel *c;
	HASH_FIND_INT(cm->channels, &id, c);
	return c;
}

uint32_t channel_get_id(struct channel *c)
{
	return c->id;
}

void * channel_get_ctx(struct channel *c)
{
	return c->ctx;
}

void channel_set_ctx(struct channel *c, void *ctx)
{
	c->ctx = ctx;
}

void channel_shutdown(struct channel *c)
{
	if (c->started) {
		c->shutting_down = true;
	} else {
		channel_free(c);
	}
}

void channel_opened(struct channel *c)
{
	c->started = true;
}

struct channel_callbacks * channel_get_callbacks(struct channel *c)
{
	return &c->type->cbs;
}

static struct tlv_packet * new_request(struct channel *c, uint32_t command_id, size_t len)
{
	struct tlv_packet *p = tlv_packet_new(TLV_PACKET_TYPE_REQUEST, len + 64);
	if (p) {
		p = tlv_packet_add_uuid(p, c->cm->td);
		p = tlv_packet_add_u32(p, TLV_TYPE_COMMAND_ID, command_id);
		p = tlv_packet_add_fmt(p, TLV_TYPE_REQUEST_ID,
				"channel-req-%d", channel_get_id(c));
		p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_get_id(c));
	}
	return p;
}

static ssize_t send_write_request(struct channel *c, void *buf, size_t buf_len)
{
	if (buf_len == 0) {
		return 0;
	}
	struct tlv_packet *p = new_request(c, COMMAND_ID_CORE_CHANNEL_WRITE, buf_len);
	p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, buf_len);
	p = tlv_packet_add_u32(p, TLV_TYPE_LENGTH, buf_len);
	return tlv_dispatcher_enqueue_response(c->cm->td, p);
};

ssize_t channel_enqueue_ex(struct channel *c, void *buf, size_t buf_len, struct tlv_packet *extra)
{
	if (buf_len == 0) {
		return 0;
	}
	struct tlv_packet *p = new_request(c, COMMAND_ID_CORE_CHANNEL_WRITE, buf_len);
	p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, buf_len);
	p = tlv_packet_add_u32(p, TLV_TYPE_LENGTH, buf_len);
	p = tlv_packet_merge_child(p, extra);
	return tlv_dispatcher_enqueue_response(c->cm->td, p);
}

ssize_t channel_enqueue(struct channel *c, void *buf, size_t buf_len)
{
	if (c->interactive) {
		return send_write_request(c, buf, buf_len);
	} else {
		return buffer_queue_add(c->queue, buf, buf_len);
	}
}

ssize_t channel_enqueue_buffer_queue(struct channel *c, struct buffer_queue *q)
{
	ssize_t enqueued_bytes = -1;
	if (c->interactive) {
		void *buf;
		ssize_t buf_len = buffer_queue_remove_all(q, &buf);
		if (buf_len <= 0) {
			goto out;
		}
		enqueued_bytes = send_write_request(c, buf, buf_len);
		free(buf);
	} else {
		enqueued_bytes = buffer_queue_move_all(c->queue, q);
	}
out:
	return enqueued_bytes;
}

ssize_t channel_dequeue(struct channel *c, void *buf, size_t buf_len)
{
	return buffer_queue_remove(c->queue, buf, buf_len);
}

size_t channel_queue_len(struct channel *c)
{
	return buffer_queue_len(c->queue);
}

int channel_send_close_request(struct channel *c)
{
	struct tlv_packet *p = new_request(c, COMMAND_ID_CORE_CHANNEL_CLOSE, 0);
	return tlv_dispatcher_enqueue_response(c->cm->td, p);
};

static void channel_postcb(struct channel *c)
{
	if (c->shutting_down) {
		c->shutting_down = false;
		channel_send_close_request(c);
		channel_free(c);
	}
}

struct channel_type * channelmgr_type_by_name(struct channelmgr *cm, char *name)
{
	struct channel_type *ct;
	HASH_FIND_STR(cm->types, name, ct);
	return ct;
}

int channelmgr_add_channel_type(struct channelmgr *cm, char *name,
    struct channel_callbacks *cbs)
{
	struct channel_type *ct = calloc(1, sizeof(*ct));
	if (ct == NULL) {
		return -1;
	}

	ct->name = strdup(name);
	ct->cbs = *cbs;
	HASH_ADD_KEYPTR(hh, cm->types, ct->name, strlen(ct->name), ct);
	return 0;
}

static struct tlv_packet *channel_open(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channelmgr *cm = mettle_get_channelmgr(m);
	int rc = TLV_RESULT_FAILURE;

	char *channel_type = tlv_packet_get_str(ctx->req, TLV_TYPE_CHANNEL_TYPE);
	if (channel_type == NULL) {
		goto out;
	}

	struct channel *c = channelmgr_channel_new(cm, channel_type);
	if (c == NULL) {
		goto out;
	}
	ctx->channel = c;
	ctx->channel_id = channel_get_id(c);

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	log_info("creating new channel of type %s", channel_type);
	/*
	 * If there is an async new callback, only handle direct failures, success
	 * handling is the responsibility of the callback.
	 */
	if (cbs->new_async_cb) {
		if (cbs->new_async_cb(ctx, c) == -1) {
			channel_free(c);
			goto out;
		} else {
			return NULL;
		}
	}

	/*
	 * If there is a sync callback, handle it directly.
	 */
	if (cbs->new_cb && cbs->new_cb(ctx, c) == -1) {
		channel_free(c);
		goto out;
	} else {
		c->started = true;
		rc = TLV_RESULT_SUCCESS;
	}

out:
	return tlv_packet_response_result(ctx, rc);
}

struct channel * tlv_handler_ctx_channel_by_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct channelmgr *cm = mettle_get_channelmgr(m);

	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_CHANNEL_ID, &ctx->channel_id)) {
		return NULL;
	}
	ctx->channel = channelmgr_channel_by_id(cm, ctx->channel_id);
	return ctx->channel;
}

static struct tlv_packet *channel_close(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	struct tlv_packet *p;
	if (cbs->free_cb && cbs->free_cb(c) == -1) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}
	channel_free(c);
	return p;
}

void channel_set_eof(struct channel *c)
{
	c->eof = true;
}

void channel_set_interactive(struct channel *c, bool enable)
{
	if (enable) {
		struct channel_callbacks *cbs = channel_get_callbacks(c);
		char buf[65535];
		ssize_t buf_len = 0;
		do {
			buf_len = cbs->read_cb(c, buf, sizeof(buf));
			if (buf_len > 0) {
				send_write_request(c, buf, buf_len);
			}
		} while (buf_len > 0);
	}

	c->interactive = enable;
}

bool channel_get_interactive(struct channel *c)
{
	return c->interactive;
}

static struct tlv_packet *channel_interact(struct tlv_handler_ctx *ctx)
{
	bool enable = false;
	tlv_packet_get_bool(ctx->req, TLV_TYPE_BOOL, &enable);

	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		/*
		 * We don't care if the caller tells us to stop interacting
		 * with a non-existent channel.
		 */
		return tlv_packet_response_result(ctx,
			enable ? TLV_RESULT_FAILURE : TLV_RESULT_SUCCESS);
	}

	channel_set_interactive(c, enable);

	tlv_dispatcher_enqueue_response(c->cm->td,
		tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS));

	channel_postcb(c);

	return NULL;
}

static struct tlv_packet *channel_eof(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	struct tlv_packet *p;
	if (cbs->eof_cb) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_bool(p, TLV_TYPE_BOOL, cbs->eof_cb(c));
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	channel_postcb(c);

	return p;
}

static struct tlv_packet *channel_seek(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	uint32_t offset, whence;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_SEEK_OFFSET, &offset) == -1 ||
	    tlv_packet_get_u32(ctx->req, TLV_TYPE_SEEK_WHENCE, &whence) == -1) {
		return tlv_packet_response_result(ctx, TLV_RESULT_EINVAL);
	}

	struct tlv_packet *p;
	if (cbs->seek_cb) {
		int rc = cbs->seek_cb(c, offset, whence);
		p = tlv_packet_response_result(ctx,
			rc == 0 ? TLV_RESULT_SUCCESS : TLV_RESULT_FAILURE);
	} else {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	channel_postcb(c);

	return p;
}

static struct tlv_packet *channel_tell(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	struct tlv_packet *p;
	if (cbs->tell_cb == NULL) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
		return p;
	}

	ssize_t offset = cbs->tell_cb(c);
	if (offset >= 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_u32(p, TLV_TYPE_SEEK_POS, offset);
	} else {
		p = tlv_packet_response_result(ctx, errno);
	}

	channel_postcb(c);

	return p;
}

static struct tlv_packet *channel_read(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	uint32_t len = 0;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &len) == -1) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	if (cbs->read_cb == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	char *buf = calloc(1, len);
	if (buf == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	ssize_t bytes_read = cbs->read_cb(c, buf, len);
	struct tlv_packet *p;
	if (bytes_read >= 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, bytes_read);
	} else {
		p = tlv_packet_response_result(ctx, errno);
	}
	free(buf);

	channel_postcb(c);

	tlv_dispatcher_enqueue_response(c->cm->td, p);
	if (c->eof) {
		channel_send_close_request(c);
	}
	return NULL;
}

static struct tlv_packet *channel_write(struct tlv_handler_ctx *ctx)
{
	struct channel *c = tlv_handler_ctx_channel_by_id(ctx);
	if (c == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	uint32_t len = 0;
	if (tlv_packet_get_u32(ctx->req, TLV_TYPE_LENGTH, &len) == -1) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	struct channel_callbacks *cbs = channel_get_callbacks(c);

	if (cbs->write_cb == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	size_t buf_len = 0;
	char *buf = tlv_packet_get_raw(ctx->req, TLV_TYPE_CHANNEL_DATA, &buf_len);
	if (buf == NULL) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}

	ssize_t bytes_written = cbs->write_cb(c, buf, len);
	struct tlv_packet *p;
	if (len == 0 || bytes_written > 0) {
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_u32(p, TLV_TYPE_LENGTH, bytes_written);
	} else {
		p = tlv_packet_response_result(ctx, errno);
	}

	channel_postcb(c);

	return p;
}

struct channelmgr *channel_get_channelmgr(struct channel *c)
{
	return c->cm;
}

void tlv_register_channelapi(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_OPEN, channel_open, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_EOF, channel_eof, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_SEEK, channel_seek, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_TELL, channel_tell, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_READ, channel_read, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_WRITE, channel_write, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_CLOSE, channel_close, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_CORE_CHANNEL_INTERACT, channel_interact, m);
}

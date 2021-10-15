/**
 * Copyright 2015 Rapid7
 * @brief Byte buffer queue
 * @file buffer_queue.h
 */

#include <stdlib.h>

#include "buffer_queue.h"
#include "utlist.h"
#include "utils.h"

struct buffer_queue {
	struct buffer {
		size_t offset, len;
		struct buffer *next;
		char *data;
	} *head;
	size_t bytes;
};

struct buffer_queue * buffer_queue_new(void)
{
	return calloc(1, sizeof(struct buffer_queue));
}

static void free_buf(struct buffer *buf)
{
	if (buf) {
		free(buf->data);
		free(buf);
	}
}

void buffer_queue_drain_all(struct buffer_queue *q)
{
	struct buffer *buf, *tmp;
	LL_FOREACH_SAFE(q->head, buf, tmp) {
		LL_DELETE(q->head, buf);
		free_buf(buf);
	}
	q->bytes = 0;
}

void buffer_queue_free(struct buffer_queue *q)
{
	if (q) {
		free(q);
	}
}

size_t buffer_queue_len(struct buffer_queue *q)
{
	return q->bytes;
}

int buffer_queue_add(struct buffer_queue *q, const void *data, size_t len)
{
	struct buffer *buf = calloc(1, sizeof(*buf));
	if (buf == NULL) {
		return -1;
	}
	buf->data = malloc(len);
	if (buf->data == NULL) {
		free_buf(buf);
		return -1;
	}

	memcpy(buf->data, data, len);
	buf->offset = 0;
	buf->len = len;

	LL_APPEND(q->head, buf);
	q->bytes += len;
	return 0;
}

int buffer_queue_add_str(struct buffer_queue *q, char *str)
{
	return buffer_queue_add(q, str, strlen(str));
}

void * buffer_queue_peek_msg(struct buffer_queue *q, size_t *len)
{
	void *data = NULL;
	if (q->head) {
		struct buffer *buf = q->head;
		data = buf->data;
		*len = buf->len;
	}
	return data;
}

void * buffer_queue_remove_msg(struct buffer_queue *q, size_t *len)
{
	void *data = NULL;
	if (q->head) {
		struct buffer *buf = q->head;
		LL_DELETE(q->head, buf);
		data = buf->data;
		*len = buf->len;
		q->bytes -= buf->len;
		free(buf);
	}
	return data;
}

size_t buffer_queue_copy(struct buffer_queue *q, void *data, size_t len)
{
	size_t copied = 0;
	struct buffer *buf;
	LL_FOREACH(q->head, buf) {
		size_t bytes = TYPESAFE_MIN(len, buf->len - buf->offset);
		memcpy(data, buf->data + buf->offset, bytes);
		data += bytes;
		len -= bytes;
		copied += bytes;
		if (len <= 0) {
			break;
		}
	}
	return copied;
}

size_t buffer_queue_drain(struct buffer_queue *q, size_t len)
{
	size_t drained = 0;
	struct buffer *buf, *tmp;
	LL_FOREACH_SAFE(q->head, buf, tmp) {
		size_t bytes = TYPESAFE_MIN(len, buf->len - buf->offset);
		len -= bytes;
		buf->offset += bytes;
		if (buf->offset == buf->len) {
			LL_DELETE(q->head, buf);
			free_buf(buf);
		}
		drained += bytes;
		if (len <= 0) {
			break;
		}
	}
	q->bytes -= drained;
	return drained;
}

size_t buffer_queue_remove(struct buffer_queue *q, void *data, size_t len)
{
	size_t removed = 0;
	struct buffer *buf, *tmp;
	LL_FOREACH_SAFE(q->head, buf, tmp) {
		size_t bytes = TYPESAFE_MIN(len, buf->len - buf->offset);
		memcpy(data, buf->data + buf->offset, bytes);
		data += bytes;
		len -= bytes;
		buf->offset += bytes;
		if (buf->offset == buf->len) {
			LL_DELETE(q->head, buf);
			free_buf(buf);
		}
		removed += bytes;
		if (len <= 0) {
			break;
		}
	}
	q->bytes -= removed;
	return removed;
}

ssize_t buffer_queue_remove_all(struct buffer_queue *q, void **data)
{
	void *buf = malloc(q->bytes);
	if (!buf) {
		return -1;
	}

	size_t bytes = buffer_queue_remove(q, buf, q->bytes);
	*data = buf;
	return bytes;
}

ssize_t buffer_queue_move_all(struct buffer_queue *dst, struct buffer_queue *src)
{
	size_t moved = 0;
	struct buffer *buf, *tmp;
	LL_FOREACH_SAFE(src->head, buf, tmp) {
		LL_DELETE(src->head, buf);
		src->bytes -= buf->len;
		LL_APPEND(dst->head, buf);
		dst->bytes += buf->len;
		moved += buf->len;
	}
	return moved;
}

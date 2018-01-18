/**
 * Copyright 2016 Rapid7
 * @brief mettle main object
 * @file channel.h
 */

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "tlv.h"

struct channel;
struct channelmgr;
struct tlv_dispatcher;

struct channelmgr * channelmgr_new(struct tlv_dispatcher *td);

void channelmgr_free(struct channelmgr *cm);

struct channel * channelmgr_channel_new(struct channelmgr *cm,
    char *channel_type);

void channel_free(struct channel *c);

struct channel * channelmgr_channel_by_id(struct channelmgr *cm, uint32_t id);

struct channel * tlv_handler_ctx_channel_by_id(struct tlv_handler_ctx *ctx);

struct channel_callbacks {
	int (*new_cb)(struct tlv_handler_ctx *tlv_ctx, struct channel *c);

	int (*new_async_cb)(struct tlv_handler_ctx *tlv_ctx, struct channel *c);

	ssize_t (*read_cb)(struct channel *c, void *buf, size_t len);

	ssize_t (*write_cb)(struct channel *c, void *buf, size_t len);

	bool (*eof_cb)(struct channel *c);

	int (*seek_cb)(struct channel *c, ssize_t offset, int whence);

	ssize_t (*tell_cb)(struct channel *c);

	int (*free_cb)(struct channel *c);
};

int channelmgr_add_channel_type(struct channelmgr *cm,
	char *name, struct channel_callbacks *cb);

struct channel_type * channelmgr_type_by_name(struct channelmgr *cm, char *name);

uint32_t channel_get_id(struct channel *c);

void * channel_get_ctx(struct channel *c);

void channel_set_ctx(struct channel *c, void *ctx);

struct channel_callbacks * channel_get_callbacks(struct channel *c);

void channel_set_eof(struct channel *c);

void channel_set_interactive(struct channel *c, bool enable);

bool channel_get_interactive(struct channel *c);

int channel_send_close_request(struct channel *c);

ssize_t channel_enqueue(struct channel *c, void *buf, size_t buf_len);

ssize_t channel_enqueue_ex(struct channel *c, void *buf, size_t buf_len,
		struct tlv_packet *extra);

ssize_t channel_enqueue_buffer_queue(struct channel *c, struct buffer_queue *bq);

ssize_t channel_dequeue(struct channel *c, void *buf, size_t buf_len);

size_t channel_queue_len(struct channel *c);

void channel_shutdown(struct channel *c);

void channel_opened(struct channel *c);

struct channelmgr *channel_get_channelmgr(struct channel *c);

void tlv_register_channelapi(struct mettle *m);

#endif

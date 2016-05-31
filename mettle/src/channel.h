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

struct channelmgr * channelmgr_new(void);

void channelmgr_free(struct channelmgr *cm);

struct channel * channelmgr_channel_new(struct channelmgr *cm, char *channel_type);

void channelmgr_channel_free(struct channelmgr *cm, struct channel *c);

struct channel *channelmgr_channel_by_id(struct channelmgr *cm, uint32_t id);

struct channel_callbacks {
	int (*new_cb)(struct tlv_handler_ctx *tlv_ctx, struct channel *c);
	struct tlv_packet * (*new_async_cb)(struct tlv_handler_ctx *tlv_ctx);

	ssize_t (*read_cb)(void *channel_ctx, char *buf, size_t len);
	struct tlv_packet * (*read_async_cb)(struct tlv_handler_ctx *tlv_ctx, size_t len);

	ssize_t (*write_cb)(void *channel_ctx, char *buf, size_t len);
	struct tlv_packet * (*write_async_cb)(struct tlv_handler_ctx *tlv_ctx, size_t len);

	bool (*eof_cb)(void *channel_ctx);

	int (*free_cb)(void *channel_ctx);
};

int channelmgr_add_channel_type(struct channelmgr *cm,
	char *name, struct channel_callbacks *cb);

struct channel_type * channelmgr_type_by_name(struct channelmgr *cm, char *name);

uint32_t channel_get_id(struct channel *c);

void * channel_get_ctx(struct channel *c);

void channel_set_ctx(struct channel *c, void *ctx);

struct channel_callbacks * channel_get_callbacks(struct channel *c);

#endif

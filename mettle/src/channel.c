#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "uthash.h"

struct channel {
	uint32_t id;
	UT_hash_handle hh;
	struct channel_type *type;
	struct channelmgr *cm;
	void *ctx;
	struct buffer_queue *queue;
	bool interactive;
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

bool channel_is_interactive(struct channel *c)
{
	return c->interactive;
}

void channel_set_interactive(struct channel *c, bool interactive)
{
	c->interactive = true;
}

struct channel_callbacks * channel_get_callbacks(struct channel *c)
{
	return &c->type->cbs;
}

static int send_write_request(struct channel *c, void *buf, size_t buf_len)
{
	struct tlv_packet *p = tlv_packet_new(TLV_PACKET_TYPE_REQUEST, buf_len + 64);
	p = tlv_packet_add_str(p, TLV_TYPE_METHOD, "core_channel_write");
	p = tlv_packet_add_fmt(p, TLV_TYPE_REQUEST_ID, "channel-req-%d", channel_get_id(c));
	p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_get_id(c));
	p = tlv_packet_add_raw(p, TLV_TYPE_CHANNEL_DATA, buf, buf_len);
	p = tlv_packet_add_u32(p, TLV_TYPE_LENGTH, buf_len);
	return tlv_dispatcher_enqueue_response(c->cm->td, p);
};

int channel_enqueue(struct channel *c, void *buf, size_t buf_len)
{
	if (c->interactive) {
		return send_write_request(c, buf, buf_len);
	} else {
		return buffer_queue_add(c->queue, buf, buf_len);
	}
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
	struct tlv_packet *p = tlv_packet_new(TLV_PACKET_TYPE_REQUEST, 64);
	p = tlv_packet_add_str(p, TLV_TYPE_METHOD, "core_channel_close");
	p = tlv_packet_add_fmt(p, TLV_TYPE_REQUEST_ID, "channel-req-%d", channel_get_id(c));
	p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_get_id(c));
	return tlv_dispatcher_enqueue_response(c->cm->td, p);
};

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

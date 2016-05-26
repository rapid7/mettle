#include "channel.h"
#include "log.h"
#include "uthash.h"

struct channel {
	uint32_t id;
	UT_hash_handle hh;
	struct channel_type *type;
	void *ctx;
};

struct channel_type {
	char *name;
	UT_hash_handle hh;
	struct channel_callbacks cbs;
};

struct channelmgr {
	struct channel *channels;
	struct channel_type *types;
	uint32_t next_channel_id;
};

struct channelmgr * channelmgr_new(void)
{
	struct channelmgr *cm = calloc(1, sizeof(*cm));
	if (cm) {
		cm->next_channel_id = 1;
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
		HASH_ADD_INT(cm->channels, id, c);
	}
	return c;
}

void channelmgr_channel_free(struct channelmgr *cm, struct channel *c)
{
	HASH_DEL(cm->channels, c);
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

struct channel_callbacks * channel_get_callbacks(struct channel *c)
{
	return &c->type->cbs;
}

struct tlv_packet * channel_tlv_packet_response_result(struct channel *c,
	struct tlv_handler_ctx *ctx, int rc)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, rc);
	p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_get_id(c));
	return p;
}

struct channel_type * channelmgr_type_by_name(struct channelmgr *cm, char *name)
{
	struct channel_type *ct;
	HASH_FIND_STR(cm->types, name, ct);
	return ct;
}

int channelmgr_add_channel_type(struct channelmgr *cm, char *name, struct channel_callbacks *cbs)
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

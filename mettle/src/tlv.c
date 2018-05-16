/**
 * Copyright 2015 Rapid7
 * @brief Meterpreter-style Type/length/value packet handler
 * @file tlv.c
 */

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <endian.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "tlv.h"
#include "uthash.h"
#include "utlist.h"
#include "mettle.h"
#include "crypttlv.h"

struct tlv_header {
	int32_t len;
	uint32_t type;
} __attribute__((packed));

struct tlv_xor_header {
	char xor_key[4];
	uint8_t session_guid[SESSION_GUID_LEN];
	uint32_t encryption_flags;
	struct tlv_header tlv;
} __attribute__((packed));

#define TLV_PREPEND_LEN 24
#define TLV_MIN_LEN 8

struct tlv_packet {
	struct tlv_header h;
	char buf[];
} __attribute__((packed));

static void tlv_xor_key(char xor_key[4])
{
	static int initialized = 0;
	if (!initialized) {
		srand(time(NULL));
		initialized = 1;
	}

	xor_key[0] = (rand() % 254) + 1;
	xor_key[1] = (rand() % 254) + 1;
	xor_key[2] = (rand() % 254) + 1;
	xor_key[3] = (rand() % 254) + 1;
}

static void *tlv_xor_bytes(char xor_key[4], void *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		((char *)buf)[i] ^= xor_key[i % 4];

	return buf;
}

struct tlv_packet *tlv_packet_new(uint32_t type, int initial_len)
{
	struct tlv_packet *p = calloc(1, sizeof(struct tlv_packet) +
			(initial_len ? initial_len : 64));
	if (p) {
		p->h.type = htonl(type);
		p->h.len = htonl(TLV_MIN_LEN);
	}
	return p;
}

void tlv_packet_free(struct tlv_packet *p)
{
	free(p);
}

void *tlv_packet_data(struct tlv_packet *p)
{
	return &p->h;
}

int tlv_packet_len(struct tlv_packet *p)
{
	return ntohl(p->h.len);
}

int tlv_packet_full_len(struct tlv_packet *p)
{
	return ntohl(p->h.len + sizeof(struct tlv_header));
}

char *tlv_packet_get_buf_str(void * buf, size_t len)
{
	char *str = buf;
	if (str != NULL) {
		if (len <= 0) {
			str = NULL;
		} else if (str[len - 1] != '\0') {
			str[len - 1] = '\0';
		}
	}
	return str;
}

void *tlv_packet_iterate(struct tlv_iterator *i, size_t *len)
{
	*len = 0;
	size_t packet_len = tlv_packet_len(i->packet) - TLV_MIN_LEN;
	while (i->offset < packet_len) {
		struct tlv_header *h = (struct tlv_header *)(i->packet->buf + i->offset);
		uint32_t type = ntohl(h->type) & ~TLV_META_TYPE_COMPRESSED;
		i->offset += ntohl(h->len);
		if (type == i->value_type) {
			*len = ntohl(h->len) - TLV_MIN_LEN;
			return h + 1;
		}
	}
	return NULL;
}

char *tlv_packet_iterate_str(struct tlv_iterator *i)
{
	size_t len;
	void *val = tlv_packet_iterate(i, &len);
	return tlv_packet_get_buf_str(val, len);
}

void *tlv_packet_get_raw(struct tlv_packet *p, uint32_t value_type, size_t *len)
{
	*len = 0;
	off_t offset = 0;
	int packet_len = tlv_packet_len(p) - TLV_MIN_LEN;
	while (offset < packet_len) {
		struct tlv_header *h = (struct tlv_header *)(p->buf + offset);
		uint32_t type = ntohl(h->type) & ~TLV_META_TYPE_COMPRESSED;
		if (type == value_type) {
			*len = ntohl(h->len) - TLV_MIN_LEN;
			return h + 1;
		}
		offset += ntohl(h->len);
	}
	return NULL;
}

char *tlv_packet_get_str(struct tlv_packet *p, uint32_t value_type)
{
	size_t len;
	void *val = tlv_packet_get_raw(p, value_type, &len);
	return tlv_packet_get_buf_str(val, len);
}

int tlv_packet_get_bool(struct tlv_packet *p, uint32_t value_type, bool *value)
{
	size_t len;
	char *buf = tlv_packet_get_raw(p, value_type, &len);
	if (!buf || len != 1)
		return -1;

	*value = *(bool *)(buf);
	return 0;
}

int tlv_packet_get_u16(struct tlv_packet *p, uint32_t value_type, uint16_t *value)
{
	size_t len;
	char *buf = tlv_packet_get_raw(p, value_type, &len);
	if (!buf || len != 2)
		return -1;

	*value = ntohs(*(uint16_t *)(buf));
	return 0;
}

int tlv_packet_get_u32(struct tlv_packet *p, uint32_t value_type, uint32_t *value)
{
	size_t len;
	char *buf = tlv_packet_get_raw(p, value_type, &len);
	if (!buf || len != 4)
		return -1;

	*value = ntohl(*(uint32_t *)(buf));
	return 0;
}

int tlv_packet_get_u64(struct tlv_packet *p, uint32_t value_type, uint64_t *value)
{
	size_t len;
	char *buf = tlv_packet_get_raw(p, value_type, &len);
	if (!buf || len != 8)
		return -1;

	*value = dnet_ntohll(*(uint64_t *)(buf));
	return 0;
}

static struct tlv_packet *
tlv_packet_add_child_raw(struct tlv_packet *p, const void *val, size_t len)
{
	int packet_len = tlv_packet_len(p);
	int new_len = packet_len + len;
	p = realloc(p, new_len);
	if (p) {
		memcpy((void *)p + packet_len, val, len);
		p->h.len = htonl(new_len);
	}
	return p;
}

struct tlv_packet *
tlv_packet_add_child(struct tlv_packet *p, struct tlv_packet *child)
{
	p = tlv_packet_add_child_raw(p, child, tlv_packet_len(child));
	tlv_packet_free(child);
	return p;
}

struct tlv_packet *
tlv_packet_merge_child(struct tlv_packet *p, struct tlv_packet *child)
{
	p = tlv_packet_add_child_raw(p, child->buf, tlv_packet_len(child) - sizeof(child->h));
	tlv_packet_free(child);
	return p;
}

struct tlv_packet * tlv_packet_add_raw(struct tlv_packet *p, uint32_t type,
		const void *val, size_t len)
{
	/*
	 * This adds memory allocation resiliency all the way down the stack
	 */
	if (p == NULL) {
		return NULL;
	}

	int packet_len = tlv_packet_len(p);
	int new_len = packet_len + TLV_MIN_LEN + len;
	p = realloc(p, new_len);
	if (p) {
		struct tlv_header *hdr = (void *)p + packet_len;
		hdr->type = htonl(type);
		hdr->len = htonl(TLV_MIN_LEN + len);
		memcpy(hdr + 1, val, len);
		p->h.len = htonl(new_len);
	}
	return p;
}

struct tlv_packet * tlv_packet_add_str(struct tlv_packet *p,
		uint32_t type, const char *str)
{
	return tlv_packet_add_raw(p, type, str, strlen(str) + 1);
}

struct tlv_packet * tlv_packet_add_u32(struct tlv_packet *p,
		uint32_t type, uint32_t val)
{
	val = htonl(val);
	return tlv_packet_add_raw(p, type, &val, sizeof(val));
}

struct tlv_packet * tlv_packet_add_result(struct tlv_packet *p, int rc)
{
	return tlv_packet_add_u32(p, TLV_TYPE_RESULT, rc);
}

struct tlv_packet * tlv_packet_add_u64(struct tlv_packet *p,
		uint32_t type, uint64_t val)
{
	return tlv_packet_add_raw(p, type, &val, sizeof(val));
}

struct tlv_packet * tlv_packet_add_bool(struct tlv_packet *p,
		uint32_t type, bool val)
{
	char val_c = val;
	return tlv_packet_add_raw(p, type, &val_c, sizeof(val_c));
}

static uint32_t bitmask32(uint32_t bits)
{
	return bits % 32 == 0 ? 0 : htonl(0xffffffff << (32 - bits));
}

static void bitmask128(uint32_t bits, uint32_t mask[4])
{
	memset(mask, 0xff, 16);
	if (bits >= 96) {
		mask[3] = bitmask32(bits % 32);
	} else if (bits >= 64) {
		mask[2] = bitmask32(bits % 32);
		memset(mask + 3, 0, 4);
	} else if (bits >= 32) {
		mask[1] = bitmask32(bits % 32);
		memset(mask + 2, 0, 8);
	} else {
		mask[0] = bitmask32(bits % 32);
		memset(mask + 1, 0, 12);
	}
}

struct tlv_packet * tlv_packet_add_addr(struct tlv_packet *p,
	uint32_t addr_tlv, uint32_t mask_tlv, uint32_t intf_index,
	const struct addr *a)
{
	if (a->addr_type == ADDR_TYPE_IP) {
		p = tlv_packet_add_raw(p, addr_tlv, a->addr_data8, IP_ADDR_LEN);
		if (mask_tlv) {
			uint32_t mask = bitmask32(a->addr_bits);
			p = tlv_packet_add_raw(p, mask_tlv, &mask, IP_ADDR_LEN);
		}
	} else if (a->addr_type == ADDR_TYPE_IP6) {
		p = tlv_packet_add_raw(p, addr_tlv, a->addr_data8, IP6_ADDR_LEN);
		if (mask_tlv) {
			uint32_t mask[4];
			bitmask128(a->addr_bits, mask);
			p = tlv_packet_add_raw(p, mask_tlv, mask, IP6_ADDR_LEN);

			/*
			 * Emit the IP6 scope on link-local addresses
			 */
			if (intf_index && a->addr_ip6.data[0] == 0xfe &&
					a->addr_ip6.data[1] == 0x80) {
				p = tlv_packet_add_raw(p, TLV_TYPE_IP6_SCOPE, &intf_index,
						sizeof(intf_index));
			}
		}
	} else {
		p = tlv_packet_add_raw(p, addr_tlv, a->addr_data8, ETH_ADDR_LEN);
	}
	return p;
}

struct tlv_packet * tlv_packet_add_fmt(struct tlv_packet *p,
		uint32_t type, char const *fmt, ...)
{
	va_list va;
	char *buffer = NULL;
	va_start(va, fmt);
	int printed = vasprintf(&buffer, fmt, va);
	if (printed != -1) {
		p = tlv_packet_add_raw(p, type, buffer, printed + 1);
		free(buffer);
	}
	va_end(va);
	return p;
}

struct tlv_packet * tlv_packet_response(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_new(TLV_PACKET_TYPE_RESPONSE,
			tlv_packet_len(ctx->req) + 32);

	p = tlv_packet_add_uuid(p, ctx->td);
	p = tlv_packet_add_str(p, TLV_TYPE_METHOD, ctx->method);

	if (ctx->channel_id) {
		p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, ctx->channel_id);
	}
	return tlv_packet_add_str(p, TLV_TYPE_REQUEST_ID, ctx->id);
};

struct tlv_packet * tlv_packet_response_result(struct tlv_handler_ctx *ctx, int rc)
{
	struct tlv_packet *p = tlv_packet_response(ctx);
	return tlv_packet_add_result(p, rc);
}

/*
 * TLV Dispatcher
 */
struct tlv_handler {
	tlv_handler_cb cb;
	void *arg;
	UT_hash_handle hh;
	char method[];
};

struct tlv_response {
	struct tlv_packet *p;
	struct tlv_response *next;
};

struct tlv_dispatcher {
	struct tlv_handler *handlers;
	tlv_response_cb response_cb;

	pthread_mutex_t mutex;
	struct tlv_response *responses;
	void *response_cb_arg;

	char *uuid;
	size_t uuid_len;

	char session_guid[SESSION_GUID_LEN];
	struct tlv_encryption_ctx *enc_ctx;
};

struct tlv_packet *tlv_packet_add_uuid(struct tlv_packet *p, struct tlv_dispatcher *td)
{
	size_t uuid_len = 0;
	const char* uuid = tlv_dispatcher_get_uuid(td, &uuid_len);
	if (uuid && uuid_len) {
		p = tlv_packet_add_raw(p, TLV_TYPE_UUID, uuid, uuid_len);
	}
	return p;
}

int tlv_dispatcher_enqueue_response(struct tlv_dispatcher *td, struct tlv_packet *p)
{
	if (p == NULL) {
		return -1;
	}

	struct tlv_response *r = malloc(sizeof(*r));
	if (r == NULL) {
		return -1;
	}

	r->p = p;

	pthread_mutex_lock(&td->mutex);
	LL_APPEND(td->responses, r);
	pthread_mutex_unlock(&td->mutex);

	if (td->response_cb) {
		td->response_cb(td, td->response_cb_arg);
	}

	return 0;
}

void * tlv_dispatcher_dequeue_response(struct tlv_dispatcher *td, bool add_prepend, size_t *len)
{
	struct tlv_packet *p = NULL;
	struct tlv_response *r = td->responses;
	void *out_buf = NULL;
	*len = 0;

	if (r) {
		pthread_mutex_lock(&td->mutex);
		LL_DELETE(td->responses, r);
		pthread_mutex_unlock(&td->mutex);

		p = r->p;
		free(r);

		void *tlv_buf = tlv_packet_data(p);
		size_t tlv_len = tlv_packet_len(p);
		size_t value_len = tlv_len - sizeof(struct tlv_header);
		size_t enc_size = ((value_len / AES_IV_LEN) + 1) * AES_IV_LEN ;
		size_t pad_len = enc_size - value_len;
		if (add_prepend) {
			// usual communications flow between server and target
			size_t out_size = enc_size + AES_IV_LEN + TLV_PREPEND_LEN;
			out_buf = calloc(out_size, 1);
			log_info("out_buf allocated as %lu", (long unsigned int)out_size);
			if (out_buf) {
				size_t length = 0;
				struct tlv_xor_header *hdr = out_buf;
				tlv_xor_key(hdr->xor_key);
				memcpy(hdr->session_guid, td->session_guid, SESSION_GUID_LEN);
				memcpy(&hdr->tlv, tlv_buf, tlv_len);
				unsigned char *tlv_data = out_buf + sizeof(struct tlv_xor_header);
				memset(tlv_data + value_len, pad_len, pad_len);
				if (td->enc_ctx != NULL) {
					unsigned char result[enc_size]; // make this 16 byte boundary for AES change process have this vary later?
					memset(result, 0, enc_size);
					if (td->enc_ctx->initialized){
						hdr->encryption_flags = htonl(td->enc_ctx->flag);
						log_info("tlv_dispatcher_dequeue_response: encrypting %lu bytes in buffer size %lu", (long unsigned int)tlv_len, (long unsigned int)enc_size);
						unsigned char iv[AES_IV_LEN];
						memcpy(iv, td->enc_ctx->iv, AES_IV_LEN); // grab iv before enc manipulates it.
						if ((length = encrypt_tlv(td->enc_ctx, tlv_data, enc_size, result)) > 0) {
							log_info("tlv_dispatcher_dequeue_response: successful encryption in %lu.", (long unsigned int)length);
							memcpy(tlv_data, iv, AES_IV_LEN);
							log_info("tlv_dispatcher_dequeue_response: injected IV");
							memcpy(tlv_data + AES_IV_LEN, result, length);
							log_info("tlv_dispatcher_dequeue_response: injected encrypted result");
							tlv_len = length + AES_IV_LEN + TLV_MIN_LEN;
							hdr->tlv.len = htonl(tlv_len);
							log_info("tlv_dispatcher_dequeue_response: updated length to %lu", (long unsigned int)tlv_len);
							log_info("tlv_dispatcher_dequeue_response: encrpyted segment loaded into TLV");
							unsigned char dec_test[length + AES_IV_LEN];
							if (decrypt_tlv(td->enc_ctx, tlv_data, length + AES_IV_LEN, dec_test) > 0)
							{
								log_info("tlv_dispatcher_dequeue_response: local decrypt is valid");
							} else {
								log_info("tlv_dispatcher_dequeue_response: failed local decrypt ********");
							}
						}
					} else {
						td->enc_ctx->initialized = true;
						log_info("tlv_dispatcher_dequeue_response: Sending XOR only encryption has not yet initialized.");
					}
				} else {
					log_info("tlv_dispatcher_dequeue_response: Sending XOR only no encryption context exists.");
				}
				log_info("tlv_dispatcher_dequeue_response: XOR tlv for output");
				tlv_xor_bytes(hdr->xor_key, &hdr->xor_key + 1, tlv_len + 20); // was this a bug or intentional
				log_info("tlv_dispatcher_dequeue_response: completed XOR of TLV");
				*len = tlv_len + TLV_PREPEND_LEN;
			}
		} else {
			// an extension, which doesn't require the GUID or XOR logic
			out_buf = calloc(tlv_len, 1);
			if (out_buf) {
				memcpy(out_buf, tlv_buf, tlv_len);
				*len = tlv_len;
			}
		}

		tlv_packet_free(p);
		log_info("tlv_dispatcher_dequeue_response: successfully free response packet");
	}

	return out_buf;
}

struct tlv_dispatcher * tlv_dispatcher_new(tlv_response_cb cb, void *cb_arg)
{
	struct tlv_dispatcher *td = calloc(1, sizeof(*td));
	if (td) {
		pthread_mutex_init(&td->mutex, NULL);
		td->response_cb = cb;
		td->response_cb_arg = cb_arg;
		char default_session_guid[SESSION_GUID_LEN] = {0};
		tlv_dispatcher_set_session_guid(td, default_session_guid);
	}
	return td;
}

int tlv_dispatcher_add_handler(struct tlv_dispatcher *td,
		const char *method, tlv_handler_cb cb, void *arg)
{
	struct tlv_handler *handler =
		calloc(1, sizeof(*handler) + strlen(method) + 1);
	if (handler == NULL) {
		return -1;
	}

	strcpy(handler->method, method);
	handler->cb = cb;
	handler->arg = arg;

	HASH_ADD_STR(td->handlers, method, handler);
	return 0;
}

void tlv_dispather_add_encryption(struct tlv_dispatcher *td, struct tlv_encryption_ctx *ctx)
{
	td->enc_ctx = ctx;
	log_info("set dispatcher encryption context");
}

void tlv_dispatcher_iter_extension_methods(struct tlv_dispatcher *td,
		const char *extension,
		void (*cb)(const char *method, void *arg), void *arg)
{
	struct tlv_handler *handler, *tmp;
	size_t extension_len = extension ? strlen(extension) : 0;
	HASH_ITER(hh, td->handlers, handler, tmp) {
		if (extension == NULL || strncmp(handler->method, extension, extension_len) == 0) {
			cb(handler->method, arg);
		}
	}
}

static struct tlv_handler * find_handler(struct tlv_dispatcher *td,
		const char *method)
{
	struct tlv_handler *handler = NULL;
	HASH_FIND_STR(td->handlers, method, handler);
	return handler;
}

void tlv_handler_ctx_free(struct tlv_handler_ctx *ctx)
{
	if (ctx) {
		tlv_packet_free(ctx->req);
		free(ctx);
	}
}

int tlv_dispatcher_process_request(struct tlv_dispatcher *td, struct tlv_packet *p)
{
	log_info("tlv_dispatcher_process_request entered");
	struct tlv_handler_ctx *ctx = calloc(1, sizeof(*ctx));

	if (ctx == NULL) {
		log_info("tlv_dispatcher_process_request called without a context");
		return -1;
	}

	ctx->req = p;
	ctx->td = td;
	ctx->method = tlv_packet_get_str(p, TLV_TYPE_METHOD);
	ctx->id = tlv_packet_get_str(p, TLV_TYPE_REQUEST_ID);

	if (ctx->method == NULL) {
		log_info("tlv_dispatcher_process_request missing TLV_TYPE_METHOD.");
		tlv_handler_ctx_free(ctx);
		return -1;
	}

	if (ctx->id == NULL) {
		log_info("tlv_dispatcher_process_request missing TLV_TYPE_REQUEST_ID.");
		ctx->id = "none";
	}
	log_info("tlv_dispatcher_process_request TLV_TYPE_METHOD: %s", ctx->method);
	log_info("tlv_dispatcher_process_request TLV_TYPE_REQUEST_ID: %s", ctx->id);

	struct tlv_packet *response = NULL;
	struct tlv_handler *handler = find_handler(td, ctx->method);
	if (handler == NULL) {
		log_error("no handler found for method: '%s'", ctx->method);
		response = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

	} else {
		log_info("processing method: '%s' id: '%s'", ctx->method, ctx->id);
		ctx->arg = handler->arg;
		response = handler->cb(ctx);
	}

	if (response) {
		tlv_handler_ctx_free(ctx);
	}

	return tlv_dispatcher_enqueue_response(td, response);
}

/*
 * This works around garbage on the socket by attempting to read past it.
 */
bool tlv_found_first_packet(struct buffer_queue *q)
{
	bool found = false;

	while (buffer_queue_len(q) >= 571) {
		struct tlv_xor_header h;
		buffer_queue_copy(q, &h, sizeof(h));
		tlv_xor_bytes(h.xor_key, &h.xor_key + 1, sizeof(h) - sizeof(h.xor_key)); // this just locates a header
		size_t len = ntohl(h.tlv.len);
		if (len == (547) && h.tlv.type == 0) {
			found = true;
			break;
		}
		buffer_queue_drain(q, 1);
	}

	return found;
}

struct tlv_packet * tlv_packet_read_buffer_queue(struct tlv_dispatcher *td , struct buffer_queue *q)
{
	/*
	 * Ensure we have enough bytes for an xor key, packet header and length
	 */
	struct tlv_xor_header h;
	if (buffer_queue_len(q) < sizeof(h)) {
		return NULL;
	}
	log_info("tlv_packet_read_buffer_queue entered");
	/*
	 * Ensure there are enough bytes for the rest of the packet
	 * This hack will soon need to die
	 */
	buffer_queue_copy(q, &h, sizeof(h));
	tlv_xor_bytes(h.xor_key, &h.session_guid, sizeof(h) - sizeof(h.xor_key)); // this is just checking length of read no enc applies
	size_t len = ntohl(h.tlv.len);
	if (len > INT_MAX || len < TLV_MIN_LEN
			|| buffer_queue_len(q) < (len + TLV_PREPEND_LEN)) {
		log_info("tlv_packet_read_buffer_queue returned with no tlv found");
		return NULL;
	}

	/*
	 * Header is OK, read the rest of the packet
	 */
	struct tlv_packet *p = malloc(TLV_MIN_LEN + len);
	if (p) {
		p->h = h.tlv;
		buffer_queue_drain(q, sizeof(h));
		len -= TLV_MIN_LEN;
		buffer_queue_remove(q, p->buf, len);
		tlv_xor_bytes(h.xor_key, p->buf, len);
		if (td == NULL) {
			log_info("tlv_packet_read_buffer_queue executed with no tlv_dispatcher.");
		}
		else {
			if (td->enc_ctx != NULL && ntohl(h.encryption_flags) != td->enc_ctx->flag)
				log_info("tlv_packet_read_buffer_queue found encryption flags 0x%X.", h.encryption_flags);
		}
		if (td != NULL && td->enc_ctx != NULL && ntohl(h.encryption_flags) == td->enc_ctx->flag) {
			log_info("tlv_packet_read_buffer_queue found an ENC_AES256 packet.");
			size_t decrypted_len = 0;
			// modify a the buffer based on expectation that encrypted PKCS1 data
			// will always be on a 16 byte boundary and the resulting data may be smaller
			unsigned char *result = calloc(len, 1);
			if ((decrypted_len = decrypt_tlv(td->enc_ctx, (unsigned char *)p->buf, len, result)) > 0) {
				memset(p->buf, 0, len);
				memcpy(p->buf, result, decrypted_len);
				free(result);
				len = decrypted_len;
				h.tlv.len = htonl(decrypted_len);
			}
			log_info("tlv_packet_read_buffer_queue successfully decrypted a packet.");
		} else {
			log_info("tlv_packet_read_buffer_queue found a standard packet.");
		}
	}

	/*
	 * Sanity check sub-TLVs
	 */
	int offset = 0;
	bool found_tlv = false;
	while (offset < len) {
		struct tlv_header *tlv = (struct tlv_header *)(p->buf + offset);
		int tlv_len = ntohl(tlv->len);
		/*
		 * Ensure the sub-TLV's fit within the packet
		 * This looks like it is would drop if padding cannot be stripped from cbc enc
		 * instead of dropping if at least on tlv is here keep all that are complete
		 * and remove any slack
		 */
		if ((tlv_len > (len - offset) || tlv_len < TLV_MIN_LEN)) {
			if (!found_tlv) {
				log_info("tlv_packet_read_buffer_queue bailed in sub-TLV.");
				free(p);
				return NULL;
			}
			else {
				break;
			}
		}
		found_tlv = true;
		log_info("tlv_packet_read_buffer_queue found a sub-TLV.");
		offset += tlv_len;
		if (tlv_len == 0) {
			break;
		}
	}

	log_info("tlv_packet_read_buffer_queue returning sanity checked packet.");
	return p;
}

int tlv_dispatcher_set_uuid(struct tlv_dispatcher *td, char *uuid, size_t len)
{
	free(td->uuid);
	td->uuid_len = 0;

	td->uuid = malloc(len);
	if (td->uuid == NULL)
		return -1;

	td->uuid_len = len;
	memcpy(td->uuid, uuid, len);
	return 0;
}

const char *tlv_dispatcher_get_uuid(struct tlv_dispatcher *td, size_t *len)
{
	*len = td->uuid_len;
	return td->uuid;
}

const char *tlv_dispatcher_get_session_guid(struct tlv_dispatcher *td)
{
	return td->session_guid;
}

int tlv_dispatcher_set_session_guid(struct tlv_dispatcher *td, char *guid)
{
	memcpy(td->session_guid, guid, SESSION_GUID_LEN);
	return 0;
}

void tlv_dispatcher_free(struct tlv_dispatcher *td)
{
	if (td) {
		struct tlv_handler *h, *h_tmp;
		HASH_ITER(hh, td->handlers, h, h_tmp) {
			free(h);
		}
		if (td->enc_ctx)
			free_tlv_encryption_ctx(td->enc_ctx);
		free(td);
	}
}

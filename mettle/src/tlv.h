/**
 * Copyright 2015 Rapid7
 * @brief Meterpreter-style Type/length/value packet handler
 * @file tlv.h
 */

#include <stdbool.h>
#include <stdint.h>

#include "buffer_queue.h"

#define TLV_PACKET_TYPE_REQUEST  0
#define TLV_PACKET_TYPE_RESPONSE 1

#define TLV_RESULT_SUCCESS 0
#define TLV_RESULT_FAILURE 1

#define TLV_CHANNEL_CLASS_BUFFERED 0
#define TLV_CHANNEL_CLASS_STREAM   1
#define TLV_CHANNEL_CLASS_DATAGRAM 2
#define TLV_CHANNEL_CLASS_POOL     3

/*
 * TLV Meta Types
 */
#define TLV_META_TYPE_NONE         0
#define TLV_META_TYPE_STRING       (1 << 16)
#define TLV_META_TYPE_UINT         (1 << 17)
#define TLV_META_TYPE_RAW          (1 << 18)
#define TLV_META_TYPE_BOOL         (1 << 19)
#define TLV_META_TYPE_QWORD        (1 << 20)
#define TLV_META_TYPE_COMPRESSED   (1 << 29)
#define TLV_META_TYPE_GROUP        (1 << 30)
#define TLV_META_TYPE_COMPLEX      (1 << 31)

#define TLV_META_TYPE_MASK         0xffff0000

struct tlv_packet;

struct tlv_packet *tlv_packet_new(uint32_t type, int initial_len);

void *tlv_packet_data(struct tlv_packet *p);

int tlv_packet_len(struct tlv_packet *p);

void *tlv_packet_get_raw(struct tlv_packet *p, uint32_t raw_type, int *len);

char *tlv_packet_get_str(struct tlv_packet *p, uint32_t value_type);

struct tlv_packet * tlv_packet_add_raw(struct tlv_packet *p, uint32_t type,
		const void *val, int len);

struct tlv_packet * tlv_packet_add_str(struct tlv_packet *p, uint32_t type, const char *str);

struct tlv_packet * tlv_packet_add_u32(struct tlv_packet *p, uint32_t type, uint32_t val);

struct tlv_packet * tlv_packet_add_u64(struct tlv_packet *p, uint32_t type, uint64_t val);

struct tlv_packet * tlv_packet_add_bool(struct tlv_packet *p, uint32_t type, bool val);

void tlv_packet_free(struct tlv_packet *p);

struct tlv_handler_ctx {
	const char *method;
	const char *id;
	struct tlv_packet *p;
};

typedef struct tlv_packet *(*tlv_handler_cb)(struct tlv_handler_ctx *, void *arg);

struct tlv_dispatcher;

struct tlv_dispatcher * tlv_dispatcher_new(void);

struct tlv_packet * tlv_process_request(struct tlv_dispatcher *td,
		struct tlv_packet *p);

struct tlv_packet * tlv_get_packet_buffer_queue(struct buffer_queue *q);

int tlv_dispatcher_add_handler(struct tlv_dispatcher *td,
		const char *method, tlv_handler_cb cb, void *arg);

struct tlv_packet * tlv_packet_response_result(struct tlv_handler_ctx *ctx, int rc);

void tlv_dispatcher_free(struct tlv_dispatcher *td);

/*
 * TLV base starting points
 */
#define TLV_RESERVED     0
#define TLV_EXTENSIONS   20000
#define TLV_USER         40000
#define TLV_TEMP         60000

/*
 * TLV Specific Types
 */
#define TLV_TYPE_ANY                   (TLV_META_TYPE_NONE    | 0)
#define TLV_TYPE_METHOD                (TLV_META_TYPE_STRING  | 1)
#define TLV_TYPE_REQUEST_ID            (TLV_META_TYPE_STRING  | 2)
#define TLV_TYPE_EXCEPTION             (TLV_META_TYPE_GROUP   | 3)
#define TLV_TYPE_RESULT                (TLV_META_TYPE_UINT    | 4)

#define TLV_TYPE_STRING                (TLV_META_TYPE_STRING  | 10)
#define TLV_TYPE_UINT                  (TLV_META_TYPE_UINT    | 11)
#define TLV_TYPE_BOOL                  (TLV_META_TYPE_BOOL    | 12)

#define TLV_TYPE_LENGTH                (TLV_META_TYPE_UINT    | 25)
#define TLV_TYPE_DATA                  (TLV_META_TYPE_RAW     | 26)
#define TLV_TYPE_FLAGS                 (TLV_META_TYPE_UINT    | 27)

#define TLV_TYPE_CHANNEL_ID            (TLV_META_TYPE_UINT    | 50)
#define TLV_TYPE_CHANNEL_TYPE          (TLV_META_TYPE_STRING  | 51)
#define TLV_TYPE_CHANNEL_DATA          (TLV_META_TYPE_RAW     | 52)
#define TLV_TYPE_CHANNEL_DATA_GROUP    (TLV_META_TYPE_GROUP   | 53)
#define TLV_TYPE_CHANNEL_CLASS         (TLV_META_TYPE_UINT    | 54)
#define TLV_TYPE_CHANNEL_PARENTID      (TLV_META_TYPE_UINT    | 55)

#define TLV_TYPE_SEEK_WHENCE           (TLV_META_TYPE_UINT    | 70)
#define TLV_TYPE_SEEK_OFFSET           (TLV_META_TYPE_UINT    | 71)
#define TLV_TYPE_SEEK_POS              (TLV_META_TYPE_UINT    | 72)

#define TLV_TYPE_EXCEPTION_CODE        (TLV_META_TYPE_UINT    | 300)
#define TLV_TYPE_EXCEPTION_STRING      (TLV_META_TYPE_STRING  | 301)

#define TLV_TYPE_LIBRARY_PATH          (TLV_META_TYPE_STRING  | 400)
#define TLV_TYPE_TARGET_PATH           (TLV_META_TYPE_STRING  | 401)
#define TLV_TYPE_MIGRATE_PID           (TLV_META_TYPE_UINT    | 402)
#define TLV_TYPE_MIGRATE_LEN           (TLV_META_TYPE_UINT    | 403)

#define TLV_TYPE_MACHINE_ID            (TLV_META_TYPE_STRING  | 460)

#define TLV_TYPE_CIPHER_NAME           (TLV_META_TYPE_STRING  | 500)
#define TLV_TYPE_CIPHER_PARAMETERS     (TLV_META_TYPE_GROUP   | 501)

#define TLV_TYPE_PEER_HOST             (TLV_META_TYPE_STRING  | 1500)
#define TLV_TYPE_PEER_PORT             (TLV_META_TYPE_UINT    | 1501)
#define TLV_TYPE_LOCAL_HOST            (TLV_META_TYPE_STRING  | 1502)
#define TLV_TYPE_LOCAL_PORT            (TLV_META_TYPE_UINT    | 1503)

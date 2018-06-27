#ifndef _STDAPI_AUDIO_MIC_H_
#define _STDAPI_AUDIO_MIC_H_

#include "tlv.h"

#define TLV_TYPE_AUDIO_DURATION        ((TLV_META_TYPE_UINT   | TLV_EXTENSIONS) + 10)
#define TLV_TYPE_AUDIO_DATA            ((TLV_META_TYPE_RAW    | TLV_EXTENSIONS) + 11)
#define TLV_TYPE_AUDIO_INTERFACE_ID    ((TLV_META_TYPE_UINT   | TLV_EXTENSIONS) + 12)
#define TLV_TYPE_AUDIO_INTERFACE_NAME  ((TLV_META_TYPE_STRING | TLV_EXTENSIONS) + 13)

struct tlv_packet *audio_mic_list(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_mic_start(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_mic_stop(struct tlv_handler_ctx *ctx);

ssize_t audio_mic_read(struct channel *c, void *buf, size_t len);
#endif

#ifndef _STDAPI_AUDIO_MIC_H_
#define _STDAPI_AUDIO_MIC_H_

struct tlv_packet *audio_mic_list(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_mic_start(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_mic_stop(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_mic_get_frame(struct tlv_handler_ctx *ctx);

#endif

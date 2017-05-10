#ifndef _STDAPI_AUDIO_INTERFACE_H_
#define _STDAPI_AUDIO_INTERFACE_H_

struct tlv_packet *audio_interface_list(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_interface_start(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_interface_stop(struct tlv_handler_ctx *ctx);
struct tlv_packet *audio_interface_get_frame(struct tlv_handler_ctx *ctx);

#endif

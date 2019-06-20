#ifndef _STDAPI_UI_H_
#define _STDAPI_UI_H_

struct tlv_packet *desktop_screenshot(struct tlv_handler_ctx *ctx);
struct tlv_packet *send_keys(struct tlv_handler_ctx *ctx);
struct tlv_packet *send_keyevent(struct tlv_handler_ctx *ctx);
struct tlv_packet *send_mouse(struct tlv_handler_ctx *ctx);

#endif

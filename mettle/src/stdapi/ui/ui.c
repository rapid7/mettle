/**
 * Copyright 2015 Rapid7
 * @brief UI API
 * @file ui.c
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "ui.h"

struct tlv_packet *desktop_screenshot(struct tlv_handler_ctx *ctx);

void ui_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_DESKTOP_SCREENSHOT
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_UI_DESKTOP_SCREENSHOT, desktop_screenshot, m);
#endif
#if HAVE_KEYBOARD
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_UI_SEND_KEYS, send_keys, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_UI_SEND_KEYEVENT, send_keyevent, m);
#endif
#if HAVE_MOUSE
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_UI_SEND_MOUSE, send_mouse, m);
#endif
}


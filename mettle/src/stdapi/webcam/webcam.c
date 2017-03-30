/**
 * Copyright 2015 Rapid7
 * @brief Webcam API
 * @file webcam.c
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

#if HAVE_WEBCAM
extern struct tlv_packet *webcam_list(struct tlv_handler_ctx *ctx);
extern struct tlv_packet *webcam_start(struct tlv_handler_ctx *ctx);
extern struct tlv_packet *webcam_stop(struct tlv_handler_ctx *ctx);
extern struct tlv_packet *webcam_get_frame(struct tlv_handler_ctx *ctx);
#endif

void webcam_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_WEBCAM
	tlv_dispatcher_add_handler(td, "webcam_list", webcam_list, m);
	tlv_dispatcher_add_handler(td, "webcam_start", webcam_start, m);
	tlv_dispatcher_add_handler(td, "webcam_stop", webcam_stop, m);
	tlv_dispatcher_add_handler(td, "webcam_get_frame", webcam_get_frame, m);
#endif
}


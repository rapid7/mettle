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
#include "webcam.h"

void webcam_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_WEBCAM
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_WEBCAM_LIST, webcam_list, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_WEBCAM_START, webcam_start, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_WEBCAM_STOP, webcam_stop, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_WEBCAM_GET_FRAME, webcam_get_frame, m);
#endif
}


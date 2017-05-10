/**
 * Copyright 2015 Rapid7
 * @brief Webcam API
 * @file interface.c
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
#include "interface.h"

void audio_interface_register_handlers(struct mettle *m)
{
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
    
#if HAVE_WEBCAM
    tlv_dispatcher_add_handler(td, "audio_interface_list", audio_interface_list, m);
    tlv_dispatcher_add_handler(td, "audio_interface_start", audio_interface_start, m);
    tlv_dispatcher_add_handler(td, "audio_interface_stop", audio_interface_stop, m);
    tlv_dispatcher_add_handler(td, "audio_interface_get_frame", audio_interface_get_frame, m);
#endif
}

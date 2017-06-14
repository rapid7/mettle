/**
 * Copyright 2017 Rapid7
 * @brief Mic API
 * @file mic.c
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
#include "mic.h"

void audio_mic_register_handlers(struct mettle *m)
{
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
    
#if HAVE_MIC
    tlv_dispatcher_add_handler(td, "audio_mic_list", audio_mic_list, m);
    tlv_dispatcher_add_handler(td, "audio_mic_start", audio_mic_start, m);
    tlv_dispatcher_add_handler(td, "audio_mic_stop", audio_mic_stop, m);
    tlv_dispatcher_add_handler(td, "audio_mic_get_frame", audio_mic_get_frame, m);
#endif
}

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
#if HAVE_MIC
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
    struct channelmgr *cm = mettle_get_channelmgr(m);

    tlv_dispatcher_add_handler(td, "audio_mic_list", audio_mic_list, m);
    tlv_dispatcher_add_handler(td, "audio_mic_start", audio_mic_start, m);
    tlv_dispatcher_add_handler(td, "audio_mic_stop", audio_mic_stop, m);

    struct channel_callbacks cbs = {
                .read_cb = audio_mic_read
    };
    channelmgr_add_channel_type(cm, "audio_mic", &cbs);
#endif
}

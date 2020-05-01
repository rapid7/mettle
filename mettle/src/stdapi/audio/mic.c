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
#include "command_ids.h"
#include "mic.h"

void audio_mic_register_handlers(struct mettle *m)
{
#if HAVE_MIC
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
    struct channelmgr *cm = mettle_get_channelmgr(m);

    tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_AUDIO_MIC_LIST, audio_mic_list, m);
    tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_AUDIO_MIC_START, audio_mic_start, m);
    tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_AUDIO_MIC_STOP, audio_mic_stop, m);

    struct channel_callbacks cbs = {
                .read_cb = audio_mic_read
    };
    channelmgr_add_channel_type(cm, "audio_mic", &cbs);
#endif
}

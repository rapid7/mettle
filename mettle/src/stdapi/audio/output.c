#include <mettle.h>

#include "channel.h"
#include "output.h"

void audio_output_register_handlers(struct mettle *m)
{
#ifdef HAVE_AUDIO_OUTPUT
    struct channelmgr *cm = mettle_get_channelmgr(m);

    struct channel_callbacks cbs = {
                .new_cb = new_audio_file,
                .write_cb = write_audio_file,
                .free_cb = terminate_audio_file,
    };
    channelmgr_add_channel_type(cm, "audio_output", &cbs);
#endif
}
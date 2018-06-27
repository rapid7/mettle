#include <stdio.h>
#include <string.h>

#include "mic.h"

FILE *arecord;

// Read all lines in `/proc/asound/pcm` if one has the `capture` mode enabled, send it
struct tlv_packet *audio_mic_list(struct tlv_handler_ctx *ctx) {
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    
    char *sound_device = NULL;
    size_t len = 0;
    ssize_t read = 0;
    FILE *proc_asound_pcm = fopen("/proc/asound/pcm", "r");
    if (proc_asound_pcm == NULL) {
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    while ((read = getline(&sound_device, &len, proc_asound_pcm)) != -1) {
	if (strstr(sound_device, "capture") != NULL) {
	    p = tlv_packet_add_str(p, TLV_TYPE_AUDIO_INTERFACE_NAME, sound_device);
	}
    }

    return p;
}

// Simply launch `arecord` on the given card ID, send sound to stdout
struct tlv_packet *audio_mic_start(struct tlv_handler_ctx *ctx) {
    uint32_t device;
    tlv_packet_get_u32(ctx->req, TLV_TYPE_AUDIO_INTERFACE_ID, &device);
    device--;

    int rc = TLV_RESULT_FAILURE;

    char cmd[100];
    sprintf(cmd, "arecord -D plughw:%d -q -f cd -t raw -r 11025 -c 1", device);
    arecord = popen(cmd, "r");
    if (arecord != NULL) {
	rc = TLV_RESULT_SUCCESS;
    }

    return tlv_packet_response_result(ctx, rc);
}

// Kill the `arecord` process
struct tlv_packet *audio_mic_stop(struct tlv_handler_ctx *ctx) {
    if (arecord != NULL) {
    	pclose(arecord);
	arecord = NULL; // So we don't try to `pclose` it again, put here as a safeguard
    }
    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

// Read `arecord` stdout and send it
ssize_t audio_mic_read(struct channel *c, void *buf, size_t len) {
    return fread(buf, 1, len, arecord);
}

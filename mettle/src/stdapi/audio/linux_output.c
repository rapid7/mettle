#include <stdio.h>
#include <stdlib.h>

#include <mettle.h>
#include "channel.h"

#include "output.h"

int terminate_audio_file(struct channel *c)
{
    // File was uploaded, play it and free the buffer
    context *ctx = channel_get_ctx(c);

    // Open pipe, we will send the content to the aplay command
    // Similar to `cat test.wav | aplay`
    FILE *pipe_fp = popen("aplay -q", "w");
    if (pipe_fp == NULL) {
        return -1;
    }

    if (fwrite(ctx->buffer, 1, ctx->size, pipe_fp) != ctx->size) {
        return -1;
    }

    pclose(pipe_fp);
    free(ctx->buffer);
    free(ctx);

    return 0;
}

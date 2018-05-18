#include <stdio.h>
#include <stdlib.h>

#include <mettle.h>
#include "channel.h"

#include "output.h"

typedef struct context {
    void *buffer;
    size_t current_size;
} context;

int new_audio_file(struct tlv_handler_ctx *tlv_ctx, struct channel *c)
{
    context ctx;

    ctx.buffer = NULL;
    ctx.current_size = 0;

    channel_set_ctx(c, &ctx);
    return 0;
}

ssize_t write_audio_file(struct channel *c, void *buf, size_t len)
{
    context *ctx = channel_get_ctx(c);

    size_t bigger = ctx->current_size + len;
    void *buffer = realloc(ctx->buffer, bigger);
    if (buffer == NULL) {
        return -1;
    }

    ctx->current_size += len;
    ctx->buffer = buffer;

    // Copy buffer
    // No need to use memcpy or whatever, let's use the barebone solution
    for (uint i = ctx->current_size - len; i < ctx->current_size; i++) {
        uint pos_in_buffer = i - ctx->current_size - len;
        ((char *)ctx->buffer)[i] = ((char *)buf)[pos_in_buffer];
    }

    return 0;
}

int terminate_audio_file(struct channel *c)
{
    // File was uploaded, play it and free the buffer
    context *ctx = channel_get_ctx(c);

    // Open pipe, we will send the content to the aplay command
    // Similar to `cat test.wav | aplay`
    FILE *pipe_fp = popen("aplay", "w");
    if (pipe_fp == NULL) {
        return -1;
    }

    if (fwrite(ctx->buffer, 1, ctx->current_size, pipe_fp) != ctx->current_size) {
        return -1;
    }

    pclose(pipe_fp);
    free(ctx->buffer);
    ctx->current_size = 0;

    return 0;
}
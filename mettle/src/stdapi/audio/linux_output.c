#include <stdio.h>
#include <stdlib.h>

#include <mettle.h>
#include "channel.h"

#include "output.h"

typedef struct context {
    size_t size;
    char *buffer;
} context;

int new_audio_file(struct tlv_handler_ctx *tlv_ctx, struct channel *c)
{
    context *ctx = malloc(sizeof(context));
    if (ctx == NULL) {
        return -1;
    }

    ctx->buffer = NULL;
    ctx->size = 0;

    channel_set_ctx(c, ctx);
    return 0;
}

ssize_t write_audio_file(struct channel *c, void *buf, size_t len)
{
    context *ctx = channel_get_ctx(c);

    ctx->size += len;
    ctx->buffer = (char *)realloc(ctx->buffer, ctx->size);
    if (ctx->buffer == NULL) {
        return -1;
    }

    // Copy buffer
    // No need to use memcpy or whatever, let's use the barebone solution
    for (size_t i = ctx->size - len; i < ctx->size; i++) {
        size_t pos_in_buffer = i - ctx->size - len;
        ctx->buffer[i] = ((char *)buf)[pos_in_buffer];
    }

    return len; // On success return the number of bytes written
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

    if (fwrite(ctx->buffer, 1, ctx->size, pipe_fp) != ctx->size) {
        return -1;
    }

    pclose(pipe_fp);
    free(ctx->buffer);
    free(ctx);

    return 0;
}
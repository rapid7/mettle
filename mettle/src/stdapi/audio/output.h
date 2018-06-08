#ifndef _STDAPI_AUDIO_OUTPUT_H_
#define _STDAPI_AUDIO_OUTPUT_H_

typedef struct context {
    size_t size;
    void *buffer;
} context;

int new_audio_file(struct tlv_handler_ctx *tlv_ctx, struct channel *c);
ssize_t write_audio_file(struct channel *c, void *buf, size_t len);
int terminate_audio_file(struct channel *c);

#endif

#import <AVFoundation/AVFoundation.h>

#include <mettle.h>
#include "channel.h"

#include "output.h"

AVAudioPlayer *audioPlayer;

int terminate_audio_file(struct channel *c)
{
    context *ctx = channel_get_ctx(c);
    @autoreleasepool {
      NSUInteger size = ctx->size;
      NSData* data = [NSData dataWithBytes:(const void *)ctx->buffer length:sizeof(unsigned char)*size];
      NSError *error;
      audioPlayer = [[AVAudioPlayer alloc] initWithData:data error:&error];
      [audioPlayer play];
    }

    free(ctx->buffer);
    free(ctx);

    return 0;
}

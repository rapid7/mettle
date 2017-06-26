#import <AVFoundation/AVFoundation.h>

#include "tlv.h"
#include "mic.h"
#include "ringbuf.h"

#define TLV_TYPE_AUDIO_DURATION        (TLV_META_TYPE_UINT   | TLV_EXTENSIONS + 10)
#define TLV_TYPE_AUDIO_DATA            (TLV_META_TYPE_RAW    | TLV_EXTENSIONS + 11)
#define TLV_TYPE_AUDIO_INTERFACE_ID    (TLV_META_TYPE_UINT   | TLV_EXTENSIONS + 12)
#define TLV_TYPE_AUDIO_INTERFACE_NAME  (TLV_META_TYPE_STRING | TLV_EXTENSIONS + 13)

@interface AudioCapture : NSObject <AVCaptureAudioDataOutputSampleBufferDelegate>
- (void) captureOutput: (AVCaptureOutput*) output
 didOutputSampleBuffer: (CMSampleBufferRef) buffer
        fromConnection: (AVCaptureConnection*) connection;
@end
@interface AudioCapture ()
{
    AVCaptureSession* session;
    size_t audioDataBufMaxLen;
    uint8_t *audioDataBuf;
    ringbuf_t audioDataRingBuf;
    unsigned int audioDataDownsampleStep;
    unsigned int audioDataBitsPerChannel;
}
- (BOOL) start: (int) deviceIndex;
- (void) stop;
- (NSData *) getFrame;
@end

@implementation AudioCapture

- (id) init
{
    self = [super init];
    audioDataBufMaxLen = 65536;
    audioDataBuf = malloc(audioDataBufMaxLen);
    if (audioDataBuf == NULL) {
      return NULL;
    }
    audioDataRingBuf = ringbuf_new(audioDataBufMaxLen);
    if (audioDataRingBuf == NULL) {
      free(audioDataBuf);
      return NULL;
    }
    audioDataDownsampleStep = 16;
    audioDataBitsPerChannel= 16;
    return self;
}

- (void) dealloc
{
    @synchronized (self) {
        
    }
}

- (BOOL) start: (int) deviceIndex
{
    session = [[AVCaptureSession alloc] init];
    [session setSessionPreset:AVCaptureSessionPresetLow];

    NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
    AVCaptureDevice *device = devices[deviceIndex];

    [device lockForConfiguration:nil];

    const AudioStreamBasicDescription *ASBD = CMAudioFormatDescriptionGetStreamBasicDescription(device.activeFormat.formatDescription);
    audioDataDownsampleStep = ((unsigned int)(ASBD->mSampleRate) / 11025) * (ASBD->mBitsPerChannel / 8) * ASBD->mChannelsPerFrame;
    audioDataBitsPerChannel = ASBD->mBitsPerChannel;
    
    NSError* error = nil;
    
    AVCaptureDeviceInput* input = [AVCaptureDeviceInput deviceInputWithDevice: device  error: &error];
    [session addInput:input];
    
    AVCaptureAudioDataOutput *output = [[AVCaptureAudioDataOutput alloc] init];
    [session addOutput:output];
    
    dispatch_queue_t queue = dispatch_queue_create("audio_interface_queue", NULL);
    [output setSampleBufferDelegate:self queue:queue];
    
    [session startRunning];
    return true;
}

- (void) stop
{
    [session stopRunning];
}

- (NSData* ) getFrame
{
    
    @synchronized (self) {
        NSData *audioPayload;
        const size_t copyLen = ringbuf_bytes_used(audioDataRingBuf);
        if (ringbuf_bytes_free(audioDataRingBuf) > 0) {
            // Ring buffer hasn't filled up, so we already have a contiguous memory space to point to...
            audioPayload = [NSData dataWithBytes:ringbuf_tail(audioDataRingBuf) length:copyLen];
        } else {
            // Ring buffer has wrapped, let's copy out the contents into a contigous memory space...
            ringbuf_memcpy_from(audioDataBuf, audioDataRingBuf, copyLen);
            audioPayload = [NSData dataWithBytes:audioDataBuf length:copyLen];
        }
        ringbuf_reset(audioDataRingBuf);
        return audioPayload;
    }
}

- (void) captureOutput: (AVCaptureOutput*) output
 didOutputSampleBuffer: (CMSampleBufferRef) buffer
        fromConnection: (AVCaptureConnection*) connection
{
    CMBlockBufferRef blockBuffer = CMSampleBufferGetDataBuffer(buffer);
    
    @synchronized (self) {
        size_t bufferLen = CMBlockBufferGetDataLength(blockBuffer);
        size_t copyLen = MIN(bufferLen, audioDataBufMaxLen);

        CMBlockBufferCopyDataBytes(blockBuffer, 0, copyLen, audioDataBuf);

        // Downsample the audio to 11.025KHz, 16-bit, single channel
        size_t downsampledLen = 0;
        for (int i = 0; i < copyLen; i += audioDataDownsampleStep) {
            switch (audioDataBitsPerChannel) {
                case 32:
                    *((uint16_t *)&audioDataBuf[downsampledLen]) = (uint16_t)(*((float *)&audioDataBuf[i]) * 32767);
                    break;
                case 24:
                    audioDataBuf[downsampledLen] = audioDataBuf[i+1];
                    audioDataBuf[downsampledLen+1] = audioDataBuf[i+2];
                    break;
                case 16:
                default:
                    audioDataBuf[downsampledLen] = audioDataBuf[i];
                    audioDataBuf[downsampledLen+1] = audioDataBuf[i+1];
                    break;
            }
            downsampledLen += 2;
        }
        // Store in a ring buffer to make sure we never lose the 'latest' captured audio.
        ringbuf_memcpy_into(audioDataRingBuf, audioDataBuf, downsampledLen);
    }
}
@end

AudioCapture* capture;

ssize_t audio_mic_read(struct channel *c, void *buf, size_t len)
{
    ssize_t readLen = 0;
    @autoreleasepool {
        NSData* wavData = [capture getFrame];
        readLen = MIN(len, wavData.length);
        memcpy(buf, wavData.bytes, readLen);
    }
    return readLen;
}

struct tlv_packet *audio_mic_start(struct tlv_handler_ctx *ctx)
{
    uint32_t deviceIndex;
    tlv_packet_get_u32(ctx->req, TLV_TYPE_AUDIO_INTERFACE_ID, &deviceIndex);
    int rc = TLV_RESULT_FAILURE;
    deviceIndex--;
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    
    @autoreleasepool {
        capture = [[AudioCapture alloc] init];
        if ([capture start:deviceIndex]) {
            rc = TLV_RESULT_SUCCESS;
        } else {
            capture = nil;
        }
    }
    return p;
}

struct tlv_packet *audio_mic_stop(struct tlv_handler_ctx *ctx)
{
    @autoreleasepool {
        [capture stop];
    }
    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *audio_mic_list(struct tlv_handler_ctx *ctx)
{
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
    for (AVCaptureDevice *device in devices) {
        const char *webcam_str = (const char *)[[device uniqueID]cStringUsingEncoding:NSUTF8StringEncoding];
        p = tlv_packet_add_str(p, TLV_TYPE_AUDIO_INTERFACE_NAME, webcam_str);
    }
    return p;
}


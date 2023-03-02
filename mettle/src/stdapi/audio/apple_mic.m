#import <AVFoundation/AVFoundation.h>

#include "mic.h"
#include "log.h"
#include "ringbuf.h"

#define AUDIO_MAX_BUFFER_SIZE         65536
#define AUDIO_TARGET_SAMPLE_RATE_HZ   11025
#define AUDIO_TARGET_BITS_PER_CHANNEL 16
#define AUDIO_TARGET_NUM_CHANNELS     1

@interface AudioCapture : NSObject <AVCaptureAudioDataOutputSampleBufferDelegate>
- (void) captureOutput: (AVCaptureOutput*) output
 didOutputSampleBuffer: (CMSampleBufferRef) buffer
        fromConnection: (AVCaptureConnection*) connection;
@end
@interface AudioCapture ()
{
}
- (BOOL) start: (int) deviceIndex;
- (void) stop;
- (NSData *) getFrame;
@end

@implementation AudioCapture

AudioCapture *capture;
AVCaptureSession* session;
uint8_t *audioDataBuf;
ringbuf_t audioDataRingBuf;
unsigned int audioDataBitsPerChannel;
unsigned int audioDataDownsampleChunkBytes;
unsigned int audioDataDownsampleStepBytes;
float audioDataDownsamplePartialStep;
float audioDataDownsamplePartialStepCount;

- (id) init
{
    self = [super init];

    // Initial store-and-downsample space for captured audio.
    // Also used as a contiguous buffer when the ring buffer has wrapped.
    audioDataBuf = malloc(AUDIO_MAX_BUFFER_SIZE);
    if (audioDataBuf == NULL) {
        log_error("failed to allocate memory for audio buffer");
        return NULL;
    }

    // Preserves most recent X seconds of captured audio until 
    // sent to MSF.
    audioDataRingBuf = ringbuf_new(AUDIO_MAX_BUFFER_SIZE);
    if (audioDataRingBuf == NULL) {
        log_error("failed to allocate memory for audio ring buffer");
        free(audioDataBuf);
        return NULL;
    }
    audioDataDownsamplePartialStepCount = 0;
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
    
#if (__MAC_OS_X_VERSION_MIN_REQUIRED <= 101406)
    NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
#else
    AVCaptureDeviceDiscoverySession *discoverySession = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInMicrophone] mediaType:AVMediaTypeAudio position:AVCaptureDevicePositionUnspecified];
    NSArray *devices = discoverySession.devices;
#endif
    AVCaptureDevice *device = devices[deviceIndex];

    // Examine available sample settings and pick a low one.
    AVCaptureDeviceFormat *low = nil;
    AudioStreamBasicDescription const *ASBDsaved = nil;
    AVCaptureDeviceFormat *formatSaved = nil;
    for (AVCaptureDeviceFormat *format in [device formats]) {
        AudioStreamBasicDescription const *ASBDcurrent = CMAudioFormatDescriptionGetStreamBasicDescription(format.formatDescription);
        if (ASBDsaved == nil) {
            ASBDsaved = ASBDcurrent;
            formatSaved = format;
        } else if (ASBDcurrent->mSampleRate <= ASBDsaved->mSampleRate && \
                ASBDcurrent->mBitsPerChannel <= ASBDsaved->mBitsPerChannel && \
                ASBDcurrent->mChannelsPerFrame <= ASBDsaved->mChannelsPerFrame) {
            // Appears to be a better candidate for sampling, just make sure it's not below our minimums.
            if (ASBDcurrent->mSampleRate >= AUDIO_TARGET_SAMPLE_RATE_HZ && \
                    ASBDcurrent->mBitsPerChannel >= AUDIO_TARGET_BITS_PER_CHANNEL && \
                    ASBDcurrent->mChannelsPerFrame >= AUDIO_TARGET_NUM_CHANNELS) {
                ASBDsaved = ASBDcurrent;
                formatSaved = format;
            }
        }
    }

    if (formatSaved) {
        if ([device lockForConfiguration:nil] == YES) {
            device.activeFormat = formatSaved;
        } else {
            // Not a show-stopper, but may use more resources than necessary on the target.
            log_info("could not acquire lock on mic device, sample settings may not be ideal");
        }
    } else {
        // Couldn't locate any sample settings, not sure how we'd get here, but log it just in case.
        log_error("could not find any sample settings");
    }

    // We'll use the following when downsampling the audio coming in...
    audioDataBitsPerChannel = ASBDsaved->mBitsPerChannel;
    audioDataDownsampleChunkBytes = (ASBDsaved->mBitsPerChannel / 8) * ASBDsaved->mChannelsPerFrame;
    audioDataDownsampleStepBytes = ((unsigned int)(ASBDsaved->mSampleRate) / AUDIO_TARGET_SAMPLE_RATE_HZ) * audioDataDownsampleChunkBytes;
    audioDataDownsamplePartialStep = (ASBDsaved->mSampleRate / (float)AUDIO_TARGET_SAMPLE_RATE_HZ) - \
            ((unsigned int)(ASBDsaved->mSampleRate) / AUDIO_TARGET_SAMPLE_RATE_HZ);
    
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
        size_t copyLen = MIN(bufferLen, AUDIO_MAX_BUFFER_SIZE);

        CMBlockBufferCopyDataBytes(blockBuffer, 0, copyLen, audioDataBuf);

        // Downsample the audio to 11.025KHz, 16-bit, single channel
        size_t downsampledLen = 0;
        for (int i = 0; i < copyLen; i += audioDataDownsampleStepBytes) {
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

            // For sample rates we don't evenly divide into, cover the "remainder"...
            audioDataDownsamplePartialStepCount += audioDataDownsamplePartialStep;
            if (audioDataDownsamplePartialStepCount > 1) {
                i += audioDataDownsampleChunkBytes;
                audioDataDownsamplePartialStepCount -= 1;
            }
        }

        // Store in a ring buffer to make sure we never lose the 'latest' captured audio.
        ringbuf_memcpy_into(audioDataRingBuf, audioDataBuf, downsampledLen);
    }
}
@end

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

BOOL mic_index_valid(uint32 deviceIndex) {
    @autoreleasepool {
#if (__MAC_OS_X_VERSION_MIN_REQUIRED <= 101406)
        NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
#else
        AVCaptureDeviceDiscoverySession *discoverySession = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInMicrophone] mediaType:AVMediaTypeAudio position:AVCaptureDevicePositionUnspecified];
        NSArray *devices = discoverySession.devices;
#endif
        if (deviceIndex < [devices count]) {
            return YES;
        }
    }
    return NO;
}

struct tlv_packet *audio_mic_start(struct tlv_handler_ctx *ctx)
{
    uint32_t deviceIndex;
    tlv_packet_get_u32(ctx->req, TLV_TYPE_AUDIO_INTERFACE_ID, &deviceIndex);
    int rc = TLV_RESULT_FAILURE;
    deviceIndex--;
    
    @autoreleasepool {
        if (mic_index_valid(deviceIndex)) {
            capture = [[AudioCapture alloc] init];
            if ([capture start:deviceIndex]) {
                rc = TLV_RESULT_SUCCESS;
            } else {
                capture = nil;
            }
        }
    }
    return tlv_packet_response_result(ctx, rc);
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
    @autoreleasepool {
#if (__MAC_OS_X_VERSION_MIN_REQUIRED <= 101406)
        NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
#else
        AVCaptureDeviceDiscoverySession *discoverySession = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInMicrophone] mediaType:AVMediaTypeAudio position:AVCaptureDevicePositionUnspecified];
        NSArray *devices = discoverySession.devices;
#endif
        for (AVCaptureDevice *device in devices) {
            const char *mic_str = (const char *)[[device uniqueID]cStringUsingEncoding:NSUTF8StringEncoding];
            p = tlv_packet_add_str(p, TLV_TYPE_AUDIO_INTERFACE_NAME, mic_str);
        }
    }
    return p;
}

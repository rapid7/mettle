#import <AVFoundation/AVFoundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIImage.h>
#else
#import <AppKit/NSImage.h>
#endif

#include "tlv.h"
#include "interface.h"

#define TLV_TYPE_AUDIO_DURATION  (TLV_META_TYPE_UINT  | TLV_EXTENSIONS + 1)
#define TLV_TYPE_AUDIO_DATA  (TLV_META_TYPE_RAW  | TLV_EXTENSIONS + 2)
#define TLV_TYPE_AUDIO_INTERFACE_NAME  (TLV_META_TYPE_UINT  | TLV_EXTENSIONS + 3)
#define TLV_TYPE_AUDIO_INTERFACE_FULLNAME  (TLV_META_TYPE_STRING  | TLV_EXTENSIONS + 4)

@interface AudioCapture : NSObject <AVCaptureAudioDataOutputSampleBufferDelegate>
- (void) captureOutput: (AVCaptureOutput*) output
 didOutputSampleBuffer: (CMSampleBufferRef) buffer
        fromConnection: (AVCaptureConnection*) connection;
@end
@interface AudioCapture ()
{
    CMSampleBufferRef head;
    AVCaptureSession* session;
    int count;
}
- (BOOL) start: (int) deviceIndex;
- (void) stop;
- (NSData *) getFrame;
@end

@implementation AudioCapture

- (id) init
{
    self = [super init];
    head = nil;
    count = 0;
    return self;
}

- (void) dealloc
{
    @synchronized (self) {
        if (head != nil) {
            CFRelease(head);
        }
    }
}

- (BOOL) start: (int) deviceIndex
{
    session = [[AVCaptureSession alloc] init];
    session.sessionPreset = AVCaptureSessionPresetMedium;
    
    NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
    AVCaptureDevice *device = devices[0];
    
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
    //Wait for 5 seconds or for 5 frames otherwise the frame is too dark
    for (int waitFrame = 0; waitFrame < 500; waitFrame++) {
        if (count > 5) {
            break;
        }
        usleep(10000);
    }
    NSLog(@"Head in Get Frame: %@", head);
    @synchronized (self) {
        if (head == nil) {
            return nil;
        }
        //return head;
        
        return [NSData dataWithBytes:head length:64];
    }
    return nil;
}

- (void) captureOutput: (AVCaptureOutput*) output
 didOutputSampleBuffer: (CMSampleBufferRef) buffer
        fromConnection: (AVCaptureConnection*) connection
{
    NSLog(@"buffer in Capture: %@", buffer);
    CMSampleBufferRef frame;
    CMSampleBufferRef prev;
    CMSampleBufferCreateCopy(kCFAllocatorDefault, buffer, &frame);
    CFRetain(frame);
    @synchronized (self) {
        prev = head;
        head = frame;
        count++;
    }
    if (prev != nil) {
        CFRelease(prev);
    }
}
@end

AudioCapture* capture;

struct tlv_packet *audio_interface_get_frame(struct tlv_handler_ctx *ctx)
{    
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    @autoreleasepool {
        NSData* wavData = [capture getFrame];
        if (wavData) {
            NSLog(@"wav: %@", wavData);
            p = tlv_packet_add_raw(p, TLV_TYPE_AUDIO_DATA, wavData.bytes, wavData.length);
        }else {
            char bytesToAppend[5] = {0x01, 0xf0, 0x64, 0x0, 0x6a};
            p = tlv_packet_add_raw(p, TLV_TYPE_AUDIO_DATA, bytesToAppend, 5);
        }
    }
    return p;
}

struct tlv_packet *audio_interface_start(struct tlv_handler_ctx *ctx)
{
    uint32_t deviceIndex = 0;
    uint32_t quality = 0;
    tlv_packet_get_u32(ctx->req, TLV_TYPE_AUDIO_INTERFACE_NAME, &deviceIndex);
    tlv_packet_get_u32(ctx->req, TLV_TYPE_AUDIO_DURATION, &quality);
    
    int rc = TLV_RESULT_FAILURE;
    @autoreleasepool {
        capture = [[AudioCapture alloc] init];
        if ([capture start:0]) {
            rc = TLV_RESULT_SUCCESS;
        } else {
            capture = nil;
        }
    }
    return tlv_packet_response_result(ctx, rc);
}

struct tlv_packet *audio_interface_stop(struct tlv_handler_ctx *ctx)
{
    @autoreleasepool {
        [capture stop];
    }
    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *audio_interface_list(struct tlv_handler_ctx *ctx)
{
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    NSArray *devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeAudio];
    for (AVCaptureDevice *device in devices) {
        const char *webcam_str = (const char *)[[device uniqueID]cStringUsingEncoding:NSUTF8StringEncoding];
        p = tlv_packet_add_str(p, TLV_TYPE_AUDIO_INTERFACE_FULLNAME, webcam_str);
    }
    return p;
}


#import <AVFoundation/AVFoundation.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include "tlv.h"
#include "ui.h"

struct tlv_packet *desktop_screenshot(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  uint32_t quality = 0;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY, &quality);
  @autoreleasepool {
    // Create semaphores to wait for async operations
    dispatch_semaphore_t contentSemaphore = dispatch_semaphore_create(0);
    dispatch_semaphore_t screenshotSemaphore = dispatch_semaphore_create(0);
    __block SCShareableContent *shareableContent = nil;
    __block CGImageRef image = NULL;

    // First, get shareable content
    [SCShareableContent getShareableContentWithCompletionHandler:^(SCShareableContent * _Nullable content, NSError * _Nullable error) {
      if (content && !error) {
        shareableContent = content;
      }
      dispatch_semaphore_signal(contentSemaphore);
    }];

    // Wait for shareable content
    dispatch_semaphore_wait(contentSemaphore, DISPATCH_TIME_FOREVER);

    if (!shareableContent || shareableContent.displays.count == 0) {
      return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    // Use the first display
    SCDisplay *display = [shareableContent.displays firstObject];
    SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];
    SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
    config.width = display.width;
    config.height = display.height;

    // Take the screenshot
    [SCScreenshotManager captureImageWithFilter:filter configuration:config completionHandler:^(CGImageRef  _Nullable sampleImage, NSError * _Nullable error) {
      if (sampleImage && !error) {
        image = CGImageRetain(sampleImage);
      }
      dispatch_semaphore_signal(screenshotSemaphore);
    }];

    // Wait for the screenshot to complete
    dispatch_semaphore_wait(screenshotSemaphore, DISPATCH_TIME_FOREVER);

    if (!image) {
      return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    CFMutableDataRef newImageData = CFDataCreateMutable(NULL, 0);
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(newImageData, (__bridge CFStringRef)UTTypeJPEG.identifier, 1, NULL);
    float compression = quality / 100;
    NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys:
                                @(compression), kCGImageDestinationLossyCompressionQuality,
                                nil];
    CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)properties);
    if (CGImageDestinationFinalize(destination)) {
      NSData *newImage = (__bridge NSData *)newImageData;
      p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
      p = tlv_packet_add_raw(p, TLV_TYPE_DESKTOP_SCREENSHOT, newImage.bytes, newImage.length);
    } else {
      p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    // Clean up the retained image
    if (image) {
      CGImageRelease(image);
    }
  }
  return p;
}

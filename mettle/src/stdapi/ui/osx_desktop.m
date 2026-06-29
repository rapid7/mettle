#import <AVFoundation/AVFoundation.h>

#include "tlv.h"
#include "ui.h"

struct tlv_packet *desktop_screenshot(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  uint32_t quality = 0;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY, &quality);
  @autoreleasepool {
  #if __MAC_OS_X_VERSION_MAX_ALLOWED >= 140000
    if ( WX_IS_MACOS_AVAILABLE(14, 4) ) // errors on lower versions of macOS 14
    {
        // TODO add ScreenKit implementation
    }
    else
#endif // macOS 10.14+
    {
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 150000
        CGImageRef image = CGDisplayCreateImage(kCGDirectMainDisplay);
#endif
    }
    CFMutableDataRef newImageData = CFDataCreateMutable(NULL, 0);
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(newImageData, kUTTypeJPEG, 1, NULL);
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
  }
  return p;
}

#import <AVFoundation/AVFoundation.h>

#include "tlv.h"
#include "ui.h"

struct tlv_packet *send_keys(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  char *keys = tlv_packet_get_str(ctx->req, TLV_TYPE_KEYS_SEND);
  @autoreleasepool {
    CFStringRef SequenceRef = CFStringCreateWithCString(NULL, keys, kCFStringEncodingUTF8);
    CFIndex SequenceLength = CFStringGetLength(SequenceRef);
    CGEventRef KeyDownEvent = CGEventCreateKeyboardEvent(NULL, 0, true);
    CGEventRef KeyUpEvent = CGEventCreateKeyboardEvent(NULL, 0, false);
    UniChar Character;
    for(CFIndex Index = 0;
        Index < SequenceLength;
        ++Index)
    {
        Character = CFStringGetCharacterAtIndex(SequenceRef, Index);
        CGEventSetFlags(KeyDownEvent, 0);
        CGEventKeyboardSetUnicodeString(KeyDownEvent, 1, &Character);
        CGEventPost(kCGHIDEventTap, KeyDownEvent);
        CGEventSetFlags(KeyUpEvent, 0);
        CGEventKeyboardSetUnicodeString(KeyUpEvent, 1, &Character);
        CGEventPost(kCGHIDEventTap, KeyUpEvent);
    }
    CFRelease(KeyUpEvent);
    CFRelease(KeyDownEvent);
    CFRelease(SequenceRef);
  }
  p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  return p;
}

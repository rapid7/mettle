#import <AVFoundation/AVFoundation.h>

#include "tlv.h"
#include "ui.h"

struct tlv_packet *send_mouse(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  uint32_t action, x, y;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_MOUSE_ACTION, &action);
  tlv_packet_get_u32(ctx->req, TLV_TYPE_MOUSE_X, &x);
  tlv_packet_get_u32(ctx->req, TLV_TYPE_MOUSE_Y, &y);
  @autoreleasepool {
    CGEventType eventType = kCGEventNull;
    CGMouseButton button = kCGMouseButtonLeft;
    CGPoint point;
    if (x == -1 && y == -1) {
      CGEventRef pointevent = CGEventCreate(NULL);
      point = CGEventGetLocation(pointevent);
    } else {
      point = CGPointMake(x, y);
    }
    if (action == 0) {
      eventType = kCGEventMouseMoved;
    } else if (action == 1) {
      eventType = kCGEventLeftMouseDown;
    } else if (action == 2) {
      eventType = kCGEventLeftMouseDown;
    } else if (action == 3) {
      eventType = kCGEventLeftMouseUp;
    } else if (action == 4) {
      eventType = kCGEventRightMouseDown;
      button = kCGMouseButtonRight;
    } else if (action == 5) {
      eventType = kCGEventRightMouseDown;
      button = kCGMouseButtonRight;
    } else if (action == 6) {
      eventType = kCGEventRightMouseUp;
      button = kCGMouseButtonRight;
    } else if (action == 7) {
      eventType = kCGEventLeftMouseDown;
    }
    CGEventRef event = CGEventCreateMouseEvent( NULL, eventType, point, button);
    CGEventPost(kCGHIDEventTap, event);
    if (action == 1) {
      eventType = kCGEventLeftMouseUp;
      CGEventRef event = CGEventCreateMouseEvent( NULL, eventType, point, button);
      CGEventPost(kCGHIDEventTap, event);
      CFRelease(event);
    }
    if (action == 4) {
      eventType = kCGEventRightMouseUp;
      CGEventRef event = CGEventCreateMouseEvent( NULL, eventType, point, button);
      CGEventPost(kCGHIDEventTap, event);
      CFRelease(event);
    }
    if (action == 7) {
      CGEventRef eventUp = CGEventCreateMouseEvent( NULL, kCGEventLeftMouseUp, point, button);
      CGEventPost(kCGHIDEventTap, eventUp);
      CGEventSetIntegerValueField(event, kCGMouseEventClickState, 2);
      CGEventPost(kCGHIDEventTap, event);
      CGEventSetIntegerValueField(eventUp, kCGMouseEventClickState, 2);
      CGEventPost(kCGHIDEventTap, eventUp);
      CFRelease(eventUp);
    }
    CFRelease(event);
  }
  p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  return p;
}

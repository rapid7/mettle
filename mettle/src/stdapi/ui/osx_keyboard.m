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

enum {
  kVK_ANSI_A                    = 0x00,
  kVK_ANSI_S                    = 0x01,
  kVK_ANSI_D                    = 0x02,
  kVK_ANSI_F                    = 0x03,
  kVK_ANSI_H                    = 0x04,
  kVK_ANSI_G                    = 0x05,
  kVK_ANSI_Z                    = 0x06,
  kVK_ANSI_X                    = 0x07,
  kVK_ANSI_C                    = 0x08,
  kVK_ANSI_V                    = 0x09,
  kVK_ANSI_B                    = 0x0B,
  kVK_ANSI_Q                    = 0x0C,
  kVK_ANSI_W                    = 0x0D,
  kVK_ANSI_E                    = 0x0E,
  kVK_ANSI_R                    = 0x0F,
  kVK_ANSI_Y                    = 0x10,
  kVK_ANSI_T                    = 0x11,
  kVK_ANSI_1                    = 0x12,
  kVK_ANSI_2                    = 0x13,
  kVK_ANSI_3                    = 0x14,
  kVK_ANSI_4                    = 0x15,
  kVK_ANSI_6                    = 0x16,
  kVK_ANSI_5                    = 0x17,
  kVK_ANSI_Equal                = 0x18,
  kVK_ANSI_9                    = 0x19,
  kVK_ANSI_7                    = 0x1A,
  kVK_ANSI_Minus                = 0x1B,
  kVK_ANSI_8                    = 0x1C,
  kVK_ANSI_0                    = 0x1D,
  kVK_ANSI_RightBracket         = 0x1E,
  kVK_ANSI_O                    = 0x1F,
  kVK_ANSI_U                    = 0x20,
  kVK_ANSI_LeftBracket          = 0x21,
  kVK_ANSI_I                    = 0x22,
  kVK_ANSI_P                    = 0x23,
  kVK_ANSI_L                    = 0x25,
  kVK_ANSI_J                    = 0x26,
  kVK_ANSI_Quote                = 0x27,
  kVK_ANSI_K                    = 0x28,
  kVK_ANSI_Semicolon            = 0x29,
  kVK_ANSI_Backslash            = 0x2A,
  kVK_ANSI_Comma                = 0x2B,
  kVK_ANSI_Slash                = 0x2C,
  kVK_ANSI_N                    = 0x2D,
  kVK_ANSI_M                    = 0x2E,
  kVK_ANSI_Period               = 0x2F,
  kVK_ANSI_Grave                = 0x32,
  kVK_ANSI_KeypadDecimal        = 0x41,
  kVK_ANSI_KeypadMultiply       = 0x43,
  kVK_ANSI_KeypadPlus           = 0x45,
  kVK_ANSI_KeypadClear          = 0x47,
  kVK_ANSI_KeypadDivide         = 0x4B,
  kVK_ANSI_KeypadEnter          = 0x4C,
  kVK_ANSI_KeypadMinus          = 0x4E,
  kVK_ANSI_KeypadEquals         = 0x51,
  kVK_ANSI_Keypad0              = 0x52,
  kVK_ANSI_Keypad1              = 0x53,
  kVK_ANSI_Keypad2              = 0x54,
  kVK_ANSI_Keypad3              = 0x55,
  kVK_ANSI_Keypad4              = 0x56,
  kVK_ANSI_Keypad5              = 0x57,
  kVK_ANSI_Keypad6              = 0x58,
  kVK_ANSI_Keypad7              = 0x59,
  kVK_ANSI_Keypad8              = 0x5B,
  kVK_ANSI_Keypad9              = 0x5C
};

enum {
  kVK_Return                    = 0x24,
  kVK_Tab                       = 0x30,
  kVK_Space                     = 0x31,
  kVK_Delete                    = 0x33,
  kVK_Escape                    = 0x35,
  kVK_Command                   = 0x37,
  kVK_Shift                     = 0x38,
  kVK_CapsLock                  = 0x39,
  kVK_Option                    = 0x3A,
  kVK_Control                   = 0x3B,
  kVK_RightShift                = 0x3C,
  kVK_RightOption               = 0x3D,
  kVK_RightControl              = 0x3E,
  kVK_Function                  = 0x3F,
  kVK_F17                       = 0x40,
  kVK_VolumeUp                  = 0x48,
  kVK_VolumeDown                = 0x49,
  kVK_Mute                      = 0x4A,
  kVK_F18                       = 0x4F,
  kVK_F19                       = 0x50,
  kVK_F20                       = 0x5A,
  kVK_F5                        = 0x60,
  kVK_F6                        = 0x61,
  kVK_F7                        = 0x62,
  kVK_F3                        = 0x63,
  kVK_F8                        = 0x64,
  kVK_F9                        = 0x65,
  kVK_F11                       = 0x67,
  kVK_F13                       = 0x69,
  kVK_F16                       = 0x6A,
  kVK_F14                       = 0x6B,
  kVK_F10                       = 0x6D,
  kVK_F12                       = 0x6F,
  kVK_F15                       = 0x71,
  kVK_Help                      = 0x72,
  kVK_Home                      = 0x73,
  kVK_PageUp                    = 0x74,
  kVK_ForwardDelete             = 0x75,
  kVK_F4                        = 0x76,
  kVK_End                       = 0x77,
  kVK_F2                        = 0x78,
  kVK_PageDown                  = 0x79,
  kVK_F1                        = 0x7A,
  kVK_LeftArrow                 = 0x7B,
  kVK_RightArrow                = 0x7C,
  kVK_DownArrow                 = 0x7D,
  kVK_UpArrow                   = 0x7E
};

int32_t getOSXKeyFromJavascriptKeyCode(uint32_t keycode)
{
  switch (keycode) {
    case 0x08:
      return kVK_Delete;
    case 0x09:
      return kVK_Tab;
    case 0x0A:
      return 0x21E4;
    case 0x0C:
      return kVK_ANSI_KeypadClear;
    case 0x0D:
      return kVK_Return;
    case 0x10:
      return kVK_Shift;
    case 0x11:
      return kVK_Control;
    case 0x12:
      return kVK_Option;
    case 0x13:
      return -1;
    case 0x14:
      return kVK_CapsLock;
    case 0x15:
      return -1;
    case 0x17:
      return -1;
    case 0x18:
      return -1;
    case 0x19:
      return -1;
    case 0x1B:
      return kVK_Escape;
    case 0x1C:
      return -1;
    case 0x1D:
      return -1;
    case 0x1E:
      return -1;
    case 0x1F:
      return -1;
    case 0x20:
      return kVK_Space;
    case 0x21:
      return kVK_PageUp;
    case 0x22:
      return kVK_PageDown;
    case 0x23:
      return kVK_End;
    case 0x24:
      return kVK_Home;
    case 0x25:
      return kVK_LeftArrow;
    case 0x26:
      return kVK_UpArrow;
    case 0x27:
      return kVK_RightArrow;
    case 0x28:
      return kVK_DownArrow;
    case 0x29:
      return -1;
    case 0x2A:
      return -1;
    case 0x2B:
      return -1;
    case 0x2C:
      return -1;
    case 0x2D:
      return kVK_Help;
    case 0x2E:
      return kVK_ForwardDelete;
    case 0x2F:
      return kVK_Help;
    case 0x30:
      return kVK_ANSI_0;
    case 0x31:
      return kVK_ANSI_1;
    case 0x32:
      return kVK_ANSI_2;
    case 0x33:
      return kVK_ANSI_3;
    case 0x34:
      return kVK_ANSI_4;
    case 0x35:
      return kVK_ANSI_5;
    case 0x36:
      return kVK_ANSI_6;
    case 0x37:
      return kVK_ANSI_7;
    case 0x38:
      return kVK_ANSI_8;
    case 0x39:
      return kVK_ANSI_9;
    case 0x41:
      return kVK_ANSI_A;
    case 0x42:
      return kVK_ANSI_B;
    case 0x43:
      return kVK_ANSI_C;
    case 0x44:
      return kVK_ANSI_D;
    case 0x45:
      return kVK_ANSI_E;
    case 0x46:
      return kVK_ANSI_F;
    case 0x47:
      return kVK_ANSI_G;
    case 0x48:
      return kVK_ANSI_H;
    case 0x49:
      return kVK_ANSI_I;
    case 0x4A:
      return kVK_ANSI_J;
    case 0x4B:
      return kVK_ANSI_K;
    case 0x4C:
      return kVK_ANSI_L;
    case 0x4D:
      return kVK_ANSI_M;
    case 0x4E:
      return kVK_ANSI_N;
    case 0x4F:
      return kVK_ANSI_O;
    case 0x50:
      return kVK_ANSI_P;
    case 0x51:
      return kVK_ANSI_Q;
    case 0x52:
      return kVK_ANSI_R;
    case 0x53:
      return kVK_ANSI_S;
    case 0x54:
      return kVK_ANSI_T;
    case 0x55:
      return kVK_ANSI_U;
    case 0x56:
      return kVK_ANSI_V;
    case 0x57:
      return kVK_ANSI_W;
    case 0x58:
      return kVK_ANSI_X;
    case 0x59:
      return kVK_ANSI_Y;
    case 0x5A:
      return kVK_ANSI_Z;
    case 0x5B:
      return kVK_Command;
    case 0x5C:
      return -1;
    case 0x5D:
      return -1;
    case 0x5F:
      return -1;
    case 0x60:
      return kVK_ANSI_Keypad0;
    case 0x61:
      return kVK_ANSI_Keypad1;
    case 0x62:
      return kVK_ANSI_Keypad2;
    case 0x63:
      return kVK_ANSI_Keypad3;
    case 0x64:
      return kVK_ANSI_Keypad4;
    case 0x65:
      return kVK_ANSI_Keypad5;
    case 0x66:
      return kVK_ANSI_Keypad6;
    case 0x67:
      return kVK_ANSI_Keypad7;
    case 0x68:
      return kVK_ANSI_Keypad8;
    case 0x69:
      return kVK_ANSI_Keypad9;
    case 0x6A:
      return kVK_ANSI_KeypadMultiply;
    case 0x6B:
      return kVK_ANSI_KeypadPlus;
    case 0x6C:
      return -1;
    case 0x6D:
      return kVK_ANSI_KeypadMinus;
    case 0x6E:
      return kVK_ANSI_KeypadDecimal;
    case 0x6F:
      return kVK_ANSI_KeypadDivide;
    case 0x70:
      return kVK_F1;
    case 0x71:
      return kVK_F2;
    case 0x72:
      return kVK_F3;
    case 0x73:
      return kVK_F4;
    case 0x74:
      return kVK_F5;
    case 0x75:
      return kVK_F6;
    case 0x76:
      return kVK_F7;
    case 0x77:
      return kVK_F8;
    case 0x78:
      return kVK_F9;
    case 0x79:
      return kVK_F10;
    case 0x7A:
      return kVK_F11;
    case 0x7B:
      return kVK_F12;
    case 0x7C:
      return kVK_F13;
    case 0x7D:
      return kVK_F14;
    case 0x7E:
      return kVK_F15;
    case 0x7F:
      return kVK_F16;
    case 0x80:
      return kVK_F17;
    case 0x81:
      return kVK_F18;
    case 0x82:
      return kVK_F19;
    case 0x83:
      return kVK_F20;
    case 0x84:
      return -1;
    case 0x85:
      return -1;
    case 0x86:
      return -1;
    case 0x87:
      return -1;
    case 0x90:
      return -1;
    case 0x91:
      return -1;
    case 0xA0:
      return kVK_Shift;
    case 0xA1:
      return kVK_Shift;
    case 0xA2:
      return kVK_Control;
    case 0xA3:
      return kVK_Control;
    case 0xA4:
      return -1;
    case 0xA5:
      return -1;
    case 0xA6:
      return -1;
    case 0xA7:
      return -1;
    case 0xA8:
      return -1;
    case 0xA9:
      return -1;
    case 0xAA:
      return -1;
    case 0xAB:
      return -1;
    case 0xAC:
      return -1;
    case 0xAD:
      return -1;
    case 0xAE:
      return -1;
    case 0xAF:
      return -1;
    case 0xB0:
      return -1;
    case 0xB1:
      return -1;
    case 0xB2:
      return -1;
    case 0xB3:
      return -1;
    case 0xB4:
      return -1;
    case 0xB5:
      return -1;
    case 0xB6:
      return -1;
    case 0xB7:
      return -1;
    case 0xBA:
      return kVK_ANSI_Semicolon;
    case 0xBB:
      return kVK_ANSI_Equal;
    case 0xBC:
      return kVK_ANSI_Comma;
    case 0xBD:
      return kVK_ANSI_Minus;
    case 0xBE:
      return kVK_ANSI_Period;
    case 0xBF:
      return kVK_ANSI_Slash;
    case 0xC0:
      return kVK_ANSI_Grave;
    case 0xDB:
      return kVK_ANSI_LeftBracket;
    case 0xDC:
      return kVK_ANSI_Backslash;
    case 0xDD:
      return kVK_ANSI_RightBracket;
    case 0xDE:
      return kVK_ANSI_Quote;
    case 0xDF:
      return -1;
    case 0xE2:
      return -1;
    case 0xE5:
      return -1;
    case 0xE7:
      return -1;
    case 0xF6:
      return -1;
    case 0xF7:
      return -1;
    case 0xF8:
      return -1;
    case 0xF9:
      return -1;
    case 0xFA:
      return -1;
    case 0xFB:
      return -1;
    case 0xFC:
      return -1;
    case 0xFD:
      return -1;
    case 0xFE:
      return kVK_ANSI_KeypadClear;
  }
  return -1;
}

void ui_send_keyevent(uint32_t keycode, bool keydown)
{
  int32_t osx_keycode = getOSXKeyFromJavascriptKeyCode(keycode);
  if (osx_keycode == -1) {
    return;
  }
  CGEventRef event = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)osx_keycode, keydown);
  CGEventPost(kCGHIDEventTap, event);
}

struct tlv_packet *send_keyevent(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  size_t buf_len = 0;
  char *buf = tlv_packet_get_raw(ctx->req, TLV_TYPE_KEYEVENT_SEND, &buf_len);
  if (buf == NULL) {
    return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
  }

  for (size_t i=0;i<buf_len;i+=8) {
    char action = buf[i];
    uint32_t keycode = *(uint32_t*)&buf[i+4];
    if (action == 1) {
      ui_send_keyevent(keycode, true);
    } else if (action == 2) {
      ui_send_keyevent(keycode, false);
    } else {
      ui_send_keyevent(keycode, true);
      ui_send_keyevent(keycode, false);
    }
  }
  p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  return p;
}


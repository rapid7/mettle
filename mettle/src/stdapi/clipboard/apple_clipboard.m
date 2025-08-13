#import <AVFoundation/AVFoundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIPasteboard.h>
#else
#import <AppKit/NSPasteboard.h>
#endif

#include "tlv.h"
#include "clipboard.h"
#include "log.h"

// Supported clipboard types for text data
#define SUPPORTED_TEXT_TYPES @[@"public.utf8-plain-text", @"public.text", @"NSStringPboardType"]

// Image types that should be skipped to prevent crashes
#define UNSUPPORTED_IMAGE_TYPES @[@"public.tiff", @"public.png", @"public.jpeg", @"com.apple.pict", @"NSPasteboardTypePDF"]

// Debug logging for clipboard operations
#define CLIPBOARD_DEBUG(fmt, ...) log_debug("[CLIPBOARD] " fmt, ##__VA_ARGS__)
#define CLIPBOARD_ERROR(fmt, ...) log_error("[CLIPBOARD] " fmt, ##__VA_ARGS__)

/**
 * @brief Check if clipboard contains only supported text data
 * @return 0 if safe to process, -1 if contains unsupported formats
 */
static int clipboard_contains_unsupported_formats() {
    @autoreleasepool {
#if TARGET_OS_IPHONE
        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        NSArray *types = [pasteboard pasteboardTypes];
#else
        NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
        NSArray *types = [pasteboard types];
#endif
        
        CLIPBOARD_DEBUG("Available clipboard types: %@", types);
        
        for (NSString *type in types) {
            // Check for image types that cause crashes
            if ([UNSUPPORTED_IMAGE_TYPES containsObject:type]) {
                CLIPBOARD_ERROR("Unsupported clipboard format detected: %@", type);
                return -1;
            }
            
            // Check for complex data types
            if ([type containsString:@"image"] || [type containsString:@"pdf"] || 
                [type containsString:@"tiff"] || [type containsString:@"png"]) {
                CLIPBOARD_ERROR("Complex clipboard format detected: %@", type);
                return -1;
            }
        }
        
        return 0;
    }
}

/**
 * @brief Safely get clipboard text with bounds checking
 * @return Valid C string or NULL if no text data available
 */
static const char *safe_get_clipboard_text() {
    @autoreleasepool {
#if TARGET_OS_IPHONE
        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        NSString *text = [pasteboard string];
#else
        NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
        
        // First check if string type is available
        if (![pasteboard availableTypeFromArray:SUPPORTED_TEXT_TYPES]) {
            CLIPBOARD_DEBUG("No supported text types found in clipboard");
            return NULL;
        }
        
        NSString *text = [pasteboard stringForType:NSPasteboardTypeString];
#endif
        
        if (!text || [text length] == 0) {
            CLIPBOARD_DEBUG("No text data found in clipboard");
            return NULL;
        }
        
        // Bounds checking - limit to reasonable size
        if ([text length] > 1024 * 1024) { // 1MB limit
            CLIPBOARD_ERROR("Clipboard text too large: %lu bytes", (unsigned long)[text length]);
            return NULL;
        }
        
        const char *result = [text UTF8String];
        if (!result) {
            CLIPBOARD_ERROR("Failed to convert clipboard text to UTF-8");
            return NULL;
        }
        
        CLIPBOARD_DEBUG("Successfully retrieved clipboard text: %lu bytes", (unsigned long)strlen(result));
        return result;
    }
}

struct tlv_packet *extapi_clipboard_set_data(struct tlv_handler_ctx *ctx)
{
    const char* clipboard_text = tlv_packet_get_str(ctx->req, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT);
    if (!clipboard_text) {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
    
    @autoreleasepool {
        NSString *text = [NSString stringWithUTF8String:clipboard_text];
        if (!text) {
            CLIPBOARD_ERROR("Invalid UTF-8 string provided");
            return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
        }
        
#if TARGET_OS_IPHONE
        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        [pasteboard setString:text];
#else
        NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents];
        [pasteboard setString:text forType:NSPasteboardTypeString];
#endif
        
        CLIPBOARD_DEBUG("Successfully set clipboard text: %lu bytes", (unsigned long)strlen(clipboard_text));
    }
    
    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

struct tlv_packet *extapi_clipboard_get_data(struct tlv_handler_ctx *ctx)
{
    struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    
    // Check for unsupported clipboard formats
    if (clipboard_contains_unsupported_formats() != 0) {
        CLIPBOARD_ERROR("Clipboard contains unsupported formats, returning empty result");
        
        struct tlv_packet *group = tlv_packet_new(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, 0);
        group = tlv_packet_add_str(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, "");
        p = tlv_packet_add_child(p, group);
        
        return p;
    }
    
    // Safely get clipboard text
    const char *clipboard_text = safe_get_clipboard_text();
    if (!clipboard_text) {
        CLIPBOARD_DEBUG("No text data available in clipboard");
        
        struct tlv_packet *group = tlv_packet_new(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, 0);
        group = tlv_packet_add_str(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, "");
        p = tlv_packet_add_child(p, group);
        
        return p;
    }
    
    // Create response with validated text data
    struct tlv_packet *group = tlv_packet_new(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, 0);
    group = tlv_packet_add_str(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, clipboard_text);
    p = tlv_packet_add_child(p, group);
    
    CLIPBOARD_DEBUG("Successfully returned clipboard data: %lu bytes", (unsigned long)strlen(clipboard_text));
    
    return p;
}

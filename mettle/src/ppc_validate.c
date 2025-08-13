/*
 * PowerPC runtime validation and architecture detection
 *
 * This module performs:
 *   - Compile-time architecture detection
 *   - Endianness check
 *   - Stack alignment validation for ABI compliance
 *
 * This ensures the mettle PowerPC payload is running
 * in a valid and expected environment before continuing execution.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "log.h"   /* mettle's logging API */

/* ---------------------------------------------------------------------
 * PowerPC architecture detection
 * ---------------------------------------------------------------------
 */
static const char* detect_powerpc_arch(void) {
#if defined(__powerpc64__)
    return "powerpc64";
#elif defined(__powerpc__)
    return "powerpc";
#elif defined(__PPC64__)
    return "ppc64";
#elif defined(__PPC__)
    return "ppc";
#else
    return "unknown";
#endif
}

/* ---------------------------------------------------------------------
 * PowerPC endianness detection
 * Returns: 1 = Big-endian, 0 = Little-endian
 * ---------------------------------------------------------------------
 */
static int detect_endianness(void) {
    union {
        uint32_t i;
        uint8_t  c[4];
    } test = {0x01020304};

    return (test.c[0] == 0x01) ? 1 : 0;
}

/* ---------------------------------------------------------------------
 * Stack alignment validation
 * PowerPC SysV ABI requires 16-byte alignment for r1 (SP)
 * ---------------------------------------------------------------------
 */
static int validate_stack_alignment(void *sp) {
    uintptr_t addr = (uintptr_t)sp;
    return (addr & 0xF) == 0;
}

/* ---------------------------------------------------------------------
 * ABI compliance check
 * Logs architecture, endianness, and stack alignment status
 * Returns: 1 if alignment is OK, 0 otherwise
 * ---------------------------------------------------------------------
 */
static int validate_powerpc_abi(void) {
    const char *arch = detect_powerpc_arch();
    int endian = detect_endianness();
    void *sp = __builtin_frame_address(0);
    int aligned = validate_stack_alignment(sp);

    log_info("PowerPC Architecture: %s", arch);
    log_info("Endianness: %s", endian ? "Big-endian" : "Little-endian");
    log_info("Stack Alignment: %s", aligned ? "OK" : "FAIL");

    return aligned;
}

/* ---------------------------------------------------------------------
 * Initialize PowerPC-specific runtime
 * Call this early in mettle startup (_start or main)
 * ---------------------------------------------------------------------
 */
void powerpc_runtime_init(void) {
    if (!validate_powerpc_abi()) {
        log_error("PowerPC ABI validation failed");
        /* If alignment fails, further execution may crash.
           Exit or handle gracefully depending on build type. */
#ifdef METTLE_STRICT_PPC
        /* Terminate process if we must enforce strict ABI compliance */
        _exit(1);
#else
        /* Non-strict: continue with warning */
        log_warn("Continuing despite ABI validation failure");
#endif
        return;
    }

    log_info("PowerPC runtime initialized successfully");
}

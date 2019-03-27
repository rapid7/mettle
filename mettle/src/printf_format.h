#ifndef PRINTF_FORMAT_H
#define PRINTF_FORMAT_H

/*
 * __MINGW_PRINTF_FORMAT is controlled by the __USE_MINGW_ANSI_STDIO macro and
 * provides the format archetype to check for. We have to match our
 * __attribute__ ((format (...))) declarations to MinGW's ANSI layer to avoid
 * triggering -Wformat on C99 formats not natively in Windows, like %z and %ll.
 *
 * Pulling in MinGW's stdio.h will set all the macros we need to make set
 * things up.
 */

#include <stdio.h>

#ifdef __MINGW_PRINTF_FORMAT
#  define METTLE_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#else
#  define METTLE_PRINTF_FORMAT printf
#endif

#endif

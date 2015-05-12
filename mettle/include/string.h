/*
 * Public domain
 * string.h compatibility shim
 */

#include_next <string.h>

#ifndef METTLE_STRING_H
#define METTLE_STRING_H

#include <sys/types.h>

#if defined(__sun) || defined(__hpux)
/* Some functions historically defined in string.h were placed in strings.h by
 * SUS. Use the same hack as OS X and FreeBSD use to work around on Solaris and HPUX.
 */
#include <strings.h>
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif

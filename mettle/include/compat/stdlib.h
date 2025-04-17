/*
 * stdlib.h compatibility shim
 * Public domain
 */

#ifdef _MSC_VER
#if _MSC_VER >= 1900
#include <../ucrt/stdlib.h>
#else
#include <../include/stdlib.h>
#endif
#else
#include_next <stdlib.h>
#endif

#ifndef LIBCRYPTOCOMPAT_STDLIB_H
#define LIBCRYPTOCOMPAT_STDLIB_H

#include <sys/types.h>
#include <stdint.h>

// Forcing the usage of embedded strtonum
// Issue: https://github.com/rapid7/mettle/issues/275
long long compat_strtonum(const char *nptr, long long minval,
		long long maxval, const char **errstr);

#ifndef HAVE_ARC4RANDOM_BUF
uint32_t arc4random(void);
void arc4random_buf(void *_buf, size_t n);
uint32_t arc4random_uniform(uint32_t upper_bound);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_SETPROCTITLE
void compat_init_setproctitle(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);
#endif

#endif

/*
 * stdlib.h compatibility shim
 * Public domain
 */

#include_next <stdlib.h>

#ifndef _COMPAT_STDLIB_H_
#define _COMPAT_STDLIB_H_

#include <stdint.h>

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval,
		long long maxval, const char **errstr);
#endif

#endif

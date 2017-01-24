/*
 * Public domain
 * arpa/inet.h compatibility shim
 */

#ifndef _WIN32
#include_next <arpa/inet.h>
#else
#include <win32netcompat.h>

#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG               0x00000400
#endif

#ifndef HAVE_INET_PTON
int inet_pton(int af, const char * src, void * dst);
#endif

#ifndef HAVE_INET_NTOP
const char * inet_ntop(int af, const void * restrict src, char * restrict dst,
    socklen_t size);
#endif

#endif

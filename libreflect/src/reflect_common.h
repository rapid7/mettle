#ifndef REFLECT_COMMON_H
#define REFLECT_COMMON_H

#include <limits.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#if DEBUG
#include <stdio.h>
#include <errno.h>
#include <string.h>
#define dprint(...) (printf(__VA_ARGS__))
#else
#define dprint(...)
#endif

#endif

/**
 * Copyright 2015 Rapid7
 * @brief Miscelaneous system functions
 * @file util.h
 */

#ifndef _UTIL_H_
#define _UTIL_H_

/*
 * COUNT_OF from Google Chromium, deals with C++ objects
 */
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/*
 * Determines min/max in a typesafe and side effect-free way
 */
#define TYPESAFE_MAX(a, b) \
   ({ __typeof__(a) _a = (a); \
		  __typeof__(b) _b = (b); \
		  _a > _b ? _a : _b; })

#define TYPESAFE_MIN(a, b) \
   ({ __typeof__(a) _a = (a); \
		  __typeof__(b) _b = (b); \
		  _a < _b ? _a : _b; })

/*
 * libuv uv_buf_t helpers
 */
#include <stdlib.h>
#include <uv.h>

static inline void uv_buf_alloc(uv_handle_t *handle, size_t size, uv_buf_t* buf)
{
	*buf = uv_buf_init(malloc(size), size);
}

static inline int uv_buf_dup(uv_buf_t *buf, void *base, size_t len)
{
	void *copy = malloc(len);
	if (copy) {
		uv_buf_alloc(NULL, len, buf);
		memcpy(buf->base, base, len);
		return 0;
	}
	return -1;
}

static inline void uv_buf_free(uv_buf_t *buf)
{
	free(buf->base);
	buf->base = NULL;
	buf->len = 0;
}

static inline int uv_buf_strdup(uv_buf_t *buf, void *str)
{
	return uv_buf_dup(buf, str, strlen(str) + 1);
}


#endif

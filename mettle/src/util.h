/**
 * @brief Misc. utility functions
 */

#ifndef _UTIL_H_
#define _UTIL_H_

/**
 * Returns static number of elements array/characters in a string
 */
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/*
 * libuv uv_buf_t helpers
 */
#include <stdlib.h>
#include <uv.h>

static inline uv_buf_t uv_buf_alloc(uv_handle_t *handle, size_t size)
{
	return uv_buf_init(malloc(size), size);
}

static inline int uv_buf_dup(uv_buf_t *buf, void *base, size_t len)
{
	void *copy = malloc(len);
	if (copy) {
		*buf = uv_buf_alloc(NULL, len);
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

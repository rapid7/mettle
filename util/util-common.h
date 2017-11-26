#ifndef _UTIL_COMMON_H_
#define _UTIL_COMMON_H_

#include <sys/types.h>

struct bin_info {
	off_t start_function;		// Where start() resides in the binary image
	off_t dynamic_linker_info;	// Where dynamic linker info resides in the image
	char magic_number[4];		// Make binary images easily identifiable
} __attribute__((packed));

#define BIN_MAGIC_NUMBER { 0x7f, 'B', 'I', 'N' }

#endif

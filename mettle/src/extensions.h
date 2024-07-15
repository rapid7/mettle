/**
 * @brief Extension mgmt/handling functions
 */

#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_

#include <stdbool.h>

struct mettle;

struct extension_process {
	struct mettle *m;
	struct process *p;
	bool ready;
};

struct extmgr *extmgr_new();

struct extension_process * extension_start_executable(struct mettle *m, const char *full_path,
	const char* args);

struct extension_process * extension_start_binary_image(struct mettle *m, const char *name,
	const unsigned char *bin_image, size_t bin_image_len, const char* args);

void extmgr_free(struct extmgr *mgr);

#endif

/**
 * @brief Extension mgmt/handling functions
 */

#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_

struct mettle;

struct extmgr *extmgr_new();

int extension_start_executable(struct mettle *m, const char *full_path,
	const char* args);

int extension_start_binary_image(struct mettle *m, const char *name,
	const unsigned char *bin_image, size_t bin_image_len, const char* args);

void extmgr_free(struct extmgr *mgr);

#endif

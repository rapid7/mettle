/**
 * @brief Extension mgmt/handling functions
 */

#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_

struct mettle;

struct extmgr *extmgr_new();

int extension_start(struct mettle *m, const char *full_path,  const char* args);

void extmgr_free(struct extmgr *mgr);

#endif

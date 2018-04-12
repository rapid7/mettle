/**
 * @brief metasploit module manager
 * @file module.h
 */

#ifndef _MODULE_H_
#define _MODULE_H_

#include <ev.h>

struct module;
struct modulemgr;

struct modulemgr * modulemgr_new(struct ev_loop *loop);

void modulemgr_register_log_cbs(struct modulemgr *mm,
	void (*line)(const char *fmt, ...),
	void (*info)(const char *fmt, ...),
	void (*good)(const char *fmt, ...),
	void (*bad)(const char *fmt, ...));

int modulemgr_load_path(struct modulemgr *mm, const char *path);

struct module ** modulemgr_find_modules(struct modulemgr *mm,
	const char *pattern, int *num_modules);

const char *module_name(struct module *m);

int module_get_metadata(struct module *m);

void module_log_info(struct module *m);

int module_run(struct module *m);

#endif

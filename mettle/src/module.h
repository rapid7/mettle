/**
 * @brief metasploit module manager
 * @file module.h
 */

#ifndef _MODULE_H_
#define _MODULE_H_

struct module;

struct modulemgr;

struct modulemgr * modulemgr_new(void);

int modulemgr_load_path(struct modulemgr *mm, const char *path);

struct module ** modulemgr_find_modules(struct modulemgr *mm,
	const char *pattern, int *num_modules);

const char *module_name(struct module *m);

#endif

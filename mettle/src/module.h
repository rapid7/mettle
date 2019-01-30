/**
 * @brief metasploit module manager
 * @file module.h
 */

#ifndef _MODULE_H_
#define _MODULE_H_

#include <ev.h>

struct module;
struct module_option;
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

void modulemgr_log_jobs(struct modulemgr *mm);

void modulemgr_kill_job(struct modulemgr *mm, int job_id);

void modulemgr_kill_all_jobs(struct modulemgr *mm);

const char *module_name(struct module *m);

int module_get_metadata(struct module *m);

void module_log_metadata(struct module *m);

void module_log_options(struct module *m);

struct module_option ** module_find_options(struct module *m,
	const char *pattern, int *num_options);

const char *module_option_name(struct module_option *m);

int module_option_set(struct module *module, const char *name, const char *value);

int module_run(struct module *m);

#endif

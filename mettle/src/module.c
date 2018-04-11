#include <stdlib.h>
#include <string.h>
#include <ftw.h>

#include "log.h"
#include "module.h"
#include "uthash.h"

struct module
{
	struct modulemgr *mm;
	char *path;
	char *name;
	UT_hash_handle hh;
};

struct modulemgr
{
	struct module *modules;
	struct {
		void (*line)(const char *fmt, ...);
		void (*info)(const char *fmt, ...);
		void (*good)(const char *fmt, ...);
		void (*bad)(const char *fmt, ...);
	} log;
	struct ev_loop *loop;
};

void modulemgr_free(struct modulemgr *mm)
{
	if (mm) {
		if (mm->modules) {
			struct module *module, *tmp;
			HASH_ITER(hh, mm->modules, module, tmp) {
				HASH_DEL(mm->modules, module);
				free(module->path);
			}
		}
		free(mm);
	}
}

struct modulemgr * modulemgr_new(struct ev_loop *loop)
{
	struct modulemgr *mm = calloc(1, sizeof(*mm));
	mm->loop = loop;
	return mm;
}

void modulemgr_register_log_cbs(struct modulemgr *mm,
	void (*line)(const char *fmt, ...),
	void (*info)(const char *fmt, ...),
	void (*good)(const char *fmt, ...),
	void (*bad)(const char *fmt, ...))
{
	mm->log.line = line;
	mm->log.info = info;
	mm->log.good = good;
	mm->log.bad = bad;
}

struct module * module_new(struct modulemgr *mm, const char *path)
{
	struct module *m = calloc(1, sizeof(*m));
	if (m) {
		m->mm = mm;
		m->path = strdup(path);
		m->name = strdup(strstr(path, "modules") + 8);
		char *ext = strchr(m->name, '.');
		if (ext) {
			*ext = '\0';
		}
	}
	return m;
}

static struct modulemgr *_mm;
static int scan_module_path(const char *path,
	const struct stat *s, int flag, struct FTW *f)
{
	if (flag == FTW_F && s->st_mode & S_IXUSR) {
		struct module *m = module_new(_mm, path);
		HASH_ADD_STR(_mm->modules, name, m);
		fprintf(stderr, "found %s\n", m->name);
	}

	return 0;
}

int modulemgr_load_path(struct modulemgr *mm, const char *path)
{
	_mm = mm;
	fprintf(stderr, "adding modules from %s\n", path);
	return (nftw(path, scan_module_path, 10, 0));
}

struct module ** modulemgr_find_modules(struct modulemgr *mm,
	const char *pattern, int *num_modules)
{
	*num_modules = 0;
	struct module *module, *tmp;
	struct module **results = NULL;
	HASH_ITER(hh, mm->modules, module, tmp) {
		if (strncmp(pattern, module->name, strlen(pattern)) == 0) {
			results = reallocarray(results, *num_modules + 1, sizeof(struct module *));
			if (results) {
				results[*num_modules] = module;
				(*num_modules)++;
			}
		}
	}
	return results;
}

const char *module_name(struct module *m)
{
	return m->name;
}

char *module_info(struct module *m)
{
	return NULL;
}

int module_run(struct module *m)
{
	return 0;
}

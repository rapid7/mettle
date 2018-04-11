#include <stdlib.h>
#include <string.h>
#include <ftw.h>

#include "json.h"
#include "log.h"
#include "module.h"
#include "process.h"
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
	struct procmgr *procmgr;
	struct json_rpc *jrpc;
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
		if (mm->procmgr) {
			procmgr_free(mm->procmgr);
		}
		if (mm->jrpc) {
			json_rpc_free(mm->jrpc);
		}
		free(mm);
	}
}

struct modulemgr * modulemgr_new(struct ev_loop *loop)
{
	struct modulemgr *mm = calloc(1, sizeof(*mm));
	mm->loop = loop;
	mm->procmgr = procmgr_new(loop);
	mm->jrpc = json_rpc_new(JSON_RPC_CHECK_VERSION);
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

static void module_exit(struct process *p, int exit_status, void *arg)
{
}

static void module_read_json(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct module *m = arg;
	struct modulemgr *mm = m->mm;
	mm->log.info("got data from module %s", m->name);
}

static void module_read_error(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct module *m = arg;
	struct modulemgr *mm = m->mm;
	mm->log.bad("got error from module %s", m->name);
}

int module_log_info(struct module *m)
{
	struct modulemgr *mm = m->mm;
	struct process_options opts = {.flags = PROCESS_CREATE_SUBSHELL};
	struct process *p = process_create_from_executable(mm->procmgr, m->path, &opts);
	process_set_callbacks(p, module_read_json, module_read_error, module_exit, m);

	int64_t id;
	struct json_object *call = json_rpc_gen_method_call(mm->jrpc,
		"describe", &id, NULL);
	const char *msg = json_object_to_json_string_ext(call, 0);
	process_write(p, msg, strlen(msg));

	mm->log.info("Module info: %s", m->name);
	mm->log.info("sending: %s", msg);

	return 0;
}

int module_run(struct module *m)
{
	return 0;
}

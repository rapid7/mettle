#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <linenoise.h>

#include "argv_split.h"
#include "log.h"
#include "mettle.h"

struct console {
	struct mettle *mettle;
	struct modulemgr *modulemgr;
	struct module *module;
	const char *name, *histfile;
	char *prompt;
	struct cmd {
		const char *name;
		const char *desc;
		void (*cb)(const char *line);
	} *cmds;
	int num_cmds;
	pthread_t thread;
	pthread_mutex_t mutex;
} console = {
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

struct cmd * console_get_cmd(const char *line)
{
	char *cmd_name = strdup(line);
	char *space = strchr(cmd_name, ' ');
	if (space) {
		*space = '\0';
	}
	struct cmd *cmd = NULL;
	for (int i = 0; i < console.num_cmds; i++) {
		if (strcmp(console.cmds[i].name, cmd_name) == 0) {
			cmd = &console.cmds[i];
			break;
		}
	}
	free(cmd_name);
	return cmd;
}

static void handle_help(const char *line)
{
	printf("Available commands:\n");
	for (int i = 0; i < console.num_cmds; i++) {
		if (console.cmds[i].desc) {
			printf("  %s\t%s\n", console.cmds[i].name, console.cmds[i].desc);
		}
	}
}

int console_register_cmd(const char *name, void (*cb)(const char *), const char *desc)
{
	struct cmd *cmd = console_get_cmd(name);
	if (cmd == NULL) {
		console.cmds = reallocarray(console.cmds,
			console.num_cmds + 1, sizeof(struct cmd));
		if (console.cmds == NULL) {
			return -1;
		}
		cmd = &console.cmds[console.num_cmds];
		cmd->name = name;
		cmd->desc = desc;
		console.num_cmds++;
	}
	cmd->cb = cb;
	return 0;
}

static void complete_use(char const *prefix, linenoiseCompletions *lc)
{
	const char *pattern = prefix + 4;
	int num_modules = 0;
	struct module **modules = modulemgr_find_modules(
		console.modulemgr, pattern, &num_modules);
	for (int i = 0; i < num_modules; i++) {
		char completion[128];
		snprintf(completion, 128, "use %s", module_name(modules[i]));
		linenoiseAddCompletion(lc, completion);
	}
	free(modules);
}

static void complete_set(char const *prefix, linenoiseCompletions *lc)
{
	if (console.module) {
		const char *pattern = prefix + 4;
		int num_options = 0;
		struct module_option **options = module_find_options(
			console.module, pattern, &num_options);
		for (int i = 0; i < num_options; i++) {
			char completion[128];
			snprintf(completion, 128, "set %s", module_option_name(options[i]));
			linenoiseAddCompletion(lc, completion);
		}
		free(options);
	}
}

static void complete_show(char const *prefix, linenoiseCompletions *lc)
{
	linenoiseAddCompletion(lc, "show options");
	linenoiseAddCompletion(lc, "show info");
}

static void complete_line(char const *prefix, linenoiseCompletions *lc)
{
	for (int i = 0; i < console.num_cmds; i++) {
		if (strncmp(prefix, console.cmds[i].name, strlen(prefix)) == 0) {
			linenoiseAddCompletion(lc, console.cmds[i].name);
		} else if (strncmp(prefix, "use ", 4) == 0) {
			complete_use(prefix, lc);
		} else if (strncmp(prefix, "set ", 4) == 0) {
			complete_set(prefix, lc);
		} else if (strncmp(prefix, "show ", 5) == 0) {
			complete_show(prefix, lc);
		}
	}
}

static void set_prompt(const char *fmt, ...)
{
	char *prompt = NULL;
	va_list va;
	int formatted = 0;

	va_start(va, fmt);
	formatted = vasprintf(&prompt, fmt, va);
	va_end(va);

	if (formatted >= 0 && prompt) {
		free(console.prompt);
		console.prompt = prompt;
	}
}

#define CURSOR_SAVE    "\033[s"
#define CURSOR_RESTORE "\033[u"
#define LINE_RESET     "\r\033[K"
#define LINE_DOWN      "\033[B"
#define COLOR_RED      "\033[31m"
#define COLOR_GREEN    "\033[32m"
#define COLOR_YELLOW   "\033[33m"
#define COLOR_BLUE     "\033[34m"
#define COLOR_MAGENTA  "\033[35m"
#define COLOR_CYAN     "\033[36m"
#define COLOR_RESET    "\033[0m"

static void console_log(const char *prefix, const char *fmt, va_list va)
{
	char *msg = NULL;
	int formatted = 0;

	formatted = vasprintf(&msg, fmt, va);

	if (formatted >= 0 && msg) {
		pthread_mutex_lock(&console.mutex);
		if (console.thread == pthread_self()) {
			printf("%s%s\n", prefix, msg);
		} else {
			printf(CURSOR_SAVE);
			printf(LINE_RESET "%s%s\n", prefix, msg);
			printf(LINE_RESET "%s", console.prompt);
			printf(CURSOR_RESTORE LINE_DOWN);
		}
		fflush(stdout);
		free(msg);
		pthread_mutex_unlock(&console.mutex);
	}
}

static void console_log_line(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	console_log("", fmt, va);
	va_end(va);
}

static void console_log_info(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	console_log(COLOR_BLUE "[*] " COLOR_RESET, fmt, va);
	va_end(va);
}

static void console_log_good(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	console_log(COLOR_GREEN "[+] " COLOR_RESET, fmt, va);
	va_end(va);
}

static void console_log_bad(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	console_log(COLOR_RED "[-] " COLOR_RESET, fmt, va);
	va_end(va);
}

static void log_cb(const char *msg)
{
	console_log_info("%s", msg);
}

static void handle_exit(const char *line)
{
	exit(0);
}

static void handle_clear(const char *line)
{
	linenoiseClearScreen();
}

static void handle_use(const char *line)
{
	int num_modules = 0;
	const char *name = line + 4;
	struct module **modules = modulemgr_find_modules(
		console.modulemgr, name, &num_modules);
	if (num_modules == 1) {
		console.module = modules[0];
		module_get_metadata(console.module);
		set_prompt("%s (%s) > ", console.name, name);
	} else {
		console_log_bad("module %s not found", name);
	}
	free(modules);
}

static void handle_set(const char *line)
{
	if (console.module) {
		size_t argc = 0;
		char **argv = NULL;
		char *buf = strdup(line);
		argv = argv_split(buf, argv, &argc);
		if (argv && argc == 3) {
			console_log_line("%s => %s", argv[1], argv[2]);
			module_option_set(console.module, argv[1], argv[2]);
		} else {
			console_log_bad("Invalid assignment");
		}
		free(buf);
	} else {
		console_log_bad("No module selected");
	}
}

static void handle_run(const char *line)
{
	if (console.module) {
		module_run(console.module);
	} else {
		console_log_bad("No module selected");
	}
}

static void handle_info(const char *line)
{
	if (console.module) {
		if (strcmp(line, "show info") == 0 || strcmp(line, "info") == 0) {
			module_log_metadata(console.module);
		} else if (strcmp(line, "show options") == 0) {
			module_log_options(console.module);
		}
	} else {
		console_log_bad("No module selected");
	}
}

static void handle_jobs(const char *line)
{
	size_t argc = 0;
	char *buf = strdup(line);
	char **argv = argv_split(buf, NULL, &argc);
	if (argc == 1) {
		modulemgr_log_jobs(console.modulemgr);
	} else if (argc == 3 && strcmp("-k", argv[1]) == 0) {
		int job_id = strtol(argv[2], NULL, 10);
		modulemgr_kill_job(console.modulemgr, job_id);
	} else if (argc == 2 && strcmp("-K", argv[1]) == 0) {
		modulemgr_kill_all_jobs(console.modulemgr);
	}
}

static void handle_back(const char *line)
{
	const char *name = line + 4;
	set_prompt("%s> ", console.name);
	console.module = NULL;
}

void *console_thread(void *arg)
{
	char *line;
	console_log_good("mettlesploit! ¯\\(º_o)/¯");
	while ((line = linenoise(console.prompt)) != NULL) {
		if (line[0] != '\0' && line[0] != '/') {
			struct cmd *cmd = console_get_cmd(line);
			if (cmd) {
				cmd->cb(line);
			} else {
			}
			linenoiseHistoryAdd(line);
			linenoiseHistorySave(console.histfile);
		}
		free(line);
	}
	return NULL;
}

void mettle_console_start_interactive(struct mettle *m)
{
	console.name = "mettle";
	console.histfile = ".mshistory";
	console.mettle = m;
	console.modulemgr = mettle_get_modulemgr(m);
	// linenoiseInstallWindowChangeHandler();
	linenoiseHistoryLoad(console.histfile);
	linenoiseSetCompletionCallback(complete_line);

	console_register_cmd("exit", handle_exit, "Exit the console");
	console_register_cmd("quit", handle_exit, NULL);
	console_register_cmd("clear", handle_clear, "Clear the screen");
	console_register_cmd("back", handle_back, "Clear the current context");
	console_register_cmd("use", handle_use, "Use a module");
	console_register_cmd("set", handle_set, "Set a module option");
	console_register_cmd("run", handle_run, "Run a module");
	console_register_cmd("info", handle_info, "Get info on a module");
	console_register_cmd("show", handle_info, "Show info on a module");
	console_register_cmd("jobs", handle_jobs, "Job management");
	console_register_cmd("help", handle_help, NULL);

	modulemgr_register_log_cbs(console.modulemgr,
		console_log_line, console_log_info, console_log_good, console_log_bad
	);

	set_prompt("%s> ", console.name);

	log_init_cb(log_cb);
	log_init_flush_thread();

	pthread_create(&console.thread, NULL, console_thread, NULL);
}

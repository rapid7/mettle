#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linenoise.h>

#include "mettle.h"

struct console {
	struct mettle *mettle;
	struct modulemgr *modulemgr;
	struct module *module;
	const char *name, *histfile;
	char *prompt;
	struct cmd {
		const char *name;
		void (*cb)(const char *line);
	} *cmds;
	int num_cmds;
} console = {0};

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

int console_register_cmd(const char *name, void (*cb)(const char *))
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

static void complete_line(char const *prefix, linenoiseCompletions *lc)
{
	for (int i = 0; i < console.num_cmds; i++) {
		if (strncmp(prefix, console.cmds[i].name, strlen(prefix)) == 0) {
			linenoiseAddCompletion(lc, console.cmds[i].name);
		} else if (strncmp(prefix, "use ", 4) == 0) {
			complete_use(prefix, lc);
		}
	}
}

static void set_prompt(const char *fmt, ...)
{
	char *prompt = NULL;
	va_list va;
	va_start(va, fmt);
	vasprintf(&prompt, fmt, va);
	va_end(va);

	if (prompt) {
		free(console.prompt);
		console.prompt = prompt;
	}
}

static void log(const char *prefix, const char *fmt, va_list va)
{
	char *msg = NULL;
	vasprintf(&msg, fmt, va);

	if (msg) {
		printf("%s%s\n", prefix, msg);
		free(msg);
	}
}

static void console_log_line(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

static void console_log_info(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log("[*] ", fmt, va);
	va_end(va);
}

static void console_log_good(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log("[+] ", fmt, va);
	va_end(va);
}

static void console_log_bad(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log("[-] ", fmt, va);
	va_end(va);
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
		set_prompt("%s (%s) > ", console.name, name);
	} else {
		console_log_bad("module %s not found", name);
	}
	free(modules);
}

static void handle_run(const char *line)
{
	if (console.module) {
		console_log_info("Running %s", module_name(console.module));
		module_run(console.module);
	} else {
		console_log_bad("No module selected");
	}
}

static void handle_info(const char *line)
{
	if (console.module) {
		console_log_info("Module info: %s", module_name(console.module));
	} else {
		console_log_bad("No module selected");
	}
}

static void handle_back(const char *line)
{
	const char *name = line + 4;
	set_prompt("%s > ", console.name);
	console.module = NULL;
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

	console_register_cmd("exit", handle_exit);
	console_register_cmd("quit", handle_exit);
	console_register_cmd("clear", handle_clear);
	console_register_cmd("back", handle_back);
	console_register_cmd("use", handle_use);
	console_register_cmd("run", handle_run);
	console_register_cmd("info", handle_info);

	modulemgr_register_log_cbs(console.modulemgr,
		console_log_line, console_log_info, console_log_good, console_log_bad
	);
		

	set_prompt("%s > ", console.name);
	char *line;
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
}

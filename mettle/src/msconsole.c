#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linenoise.h>

struct ms {
	struct cmd {
		const char *name;
		void (*cb)(struct ms *);
	} *cmds;
	int num_cmds;
} ms = {0};

struct cmd * ms_get_cmd(const char *name)
{
	for (int i = 0; i < ms.num_cmds; i++) {
		if (strcmp(ms.cmds[i].name, name) == 0) {
			return &ms.cmds[i];
		}
	}
	return NULL;
}

int ms_register_cmd(const char *name, void (*cb)(struct ms *))
{
	struct cmd *cmd = ms_get_cmd(name);
	if (cmd == NULL) {
		ms.cmds = reallocarray(ms.cmds, ms.num_cmds + 1, sizeof(struct cmd));
		if (ms.cmds == NULL) {
			return -1;
		}
		cmd = &ms.cmds[ms.num_cmds];
		cmd->name = name;
		ms.num_cmds++;
	}
	cmd->cb = cb;
	return 0;
}

static void completion_hook(char const *prefix, linenoiseCompletions *lc)
{
	for (int i = 0; i < ms.num_cmds; i++) {
		if (strncmp(prefix, ms.cmds[i].name, strlen(prefix)) == 0) {
			linenoiseAddCompletion(lc, ms.cmds[i].name);
		}
	}
}

void ms_handle_eol(struct ms *ms)
{
	exit(0);
}

void ms_handle_break(struct ms *ms)
{
}

void ms_handle_exit(struct ms *ms)
{
	exit(0);
}

void ms_handle_clear(struct ms *ms)
{
	linenoiseClearScreen();
}

void ms_start_interactive(void)
{
	linenoiseInstallWindowChangeHandler();
	linenoiseHistoryLoad(".mshistory");
	linenoiseSetCompletionCallback(completion_hook);

	ms_register_cmd("exit", ms_handle_exit);
	ms_register_cmd("quit", ms_handle_exit);
	ms_register_cmd("clear", ms_handle_clear);

	const char *prompt = "\x1b[1;32mmettle\x1b[0m> ";
	do {
		char *res = linenoise(prompt);
		if (res == NULL || *res == '\0') {
			if (res == NULL) {
				int key = linenoiseKeyType();
				if (key == 1) {
					ms_handle_break(&ms);
				} else if (key == 2) {
					ms_handle_eol(&ms);
				}
			}
			free(res);
			continue;
		} else {
			struct cmd *cmd = ms_get_cmd(res);
			if (cmd) {
				cmd->cb(&ms);
			}
		}

		linenoiseHistoryAdd(res);
		free(res);
	} while (1);
}

int main(int argc, char **argv)
{
	ms_start_interactive();
}

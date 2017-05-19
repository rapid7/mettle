/**
 * @brief Service Management Functions
 * @file service_win.c
 */

#include "service.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int start_service(const char *cmd)
{
	char *cmdline;
	asprintf(&cmdline, "cmd.exe \"start /b %s\"", cmd);
	system(cmdline);
	exit(0);
	return 0;
}

static char *service_name = NULL;

void set_service_name(const char *name)
{
	char *tmp = strdup(name);
	char *base = strdup(basename(tmp));
	char *ext = strstr(base, ".exe");
	if (ext) {
		ext[0] = '\0';
	}
	service_name = base;
	free(tmp);
}

/**
 * @brief Service Management Functions
 * @file service_win.c
 */

#include "service.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int background_service(const char *cmd)
{
	char *cmdline;
	asprintf(&cmdline, "cmd.exe /q /c \"start /b %s\"", cmd);
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

int start_service(const char *name, const char *cmd, enum persist_type persist)
{
	switch (persist) {
		case persist_none:
			return background_service(cmd);
		case persist_install:
		case persist_uninstall:
			return -1;
	}
	return -1;
}

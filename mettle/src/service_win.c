/**
 * @brief Service Management Functions
 * @file service_win.c
 */

#include "service.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

int background_service(const char *path, const char *args)
{
	char *cmdline;
	asprintf(&cmdline, "cmd.exe /q /c \"start /b %s %s\"", path, args);
	system(cmdline);
	exit(0);
	return 0;
}

/*
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

int install_service(const char *name, const char *display_name)
{
	int rc = -1;
	SC_HANDLE svc = NULL, scm = NULL;

	SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERICE);
	if (scm == NULL) {
		log_error("could not open SCM");
		return -1;
	}
*/

int start_service(const char *name, const char *path, const char *args,
	enum persist_type persist)
{
	switch (persist) {
		case persist_none:
			return background_service(path, args);
		case persist_install:
		case persist_uninstall:
			return -1;
	}
	return -1;
}

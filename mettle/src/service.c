/**
 * @brief Service Management Functions
 * @file service.c
 */

#include "service.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

int fork_service(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		log_error("could not fork: %s", strerror(errno));
		return -1;
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/*
	 * Prevent open(1) from allocating controling TTYs
	 */
	pid_t sid = setsid();
	if (sid < 0) {
		log_error("could not get new SID: %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		log_error("could not fork: %s", strerror(errno));
		return -1;
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/*
	 * Update standard file descriptors
	 */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	if (open("/dev/null", O_RDONLY) == -1) {
		log_error("failed to reopen stdin: %s", strerror(errno));
	}
	if (open("/dev/null", O_RDONLY) == -1) {
		log_error("failed to reopen stdout: %s", strerror(errno));
	}
	if (open("/dev/null", O_RDONLY) == -1) {
		log_error("failed to reopen stderr: %s", strerror(errno));
	}

	return 0;
}

int start_service(const char *name, const char *path, const char *args,
	enum persist_type persist)
{
	switch (persist) {
		case persist_none:
			return fork_service();
		case persist_install:
		case persist_uninstall:
			return -1;
	}
	return -1;
}

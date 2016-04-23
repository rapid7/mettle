/**
 * Copyright 2015 Rapid7
 * @brief Test harness
 * @file main.c
 */

#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "mettle.h"

void usage(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("  -h, --help     display help\n");
	printf("  -u, --uri      add connection URI\n");
	printf("\n");
	exit(1);
}

int parse_cmdline(int argc, char * const argv[], struct mettle *m)
{
	int c = 0;
	int index = 0;
	char *name = strdup(argv[0]);

	struct option options[] = {
		{"uri",              required_argument, NULL, 'u'},
		{ 0, 0, NULL, 0 }
	};
	const char *short_options = "hu:";

	while ((c = getopt_long(argc, argv, short_options, options, &index)) != -1) {
		switch (c) {
		case 'u':
			mettle_add_server_uri(m, optarg);
			break;
		case 'h':
		default:
			usage(basename(name));
		}
	}

	free(name);

	return 0;
}

int main(int argc, char * argv[])
{
	/*
	 * Disable SIGPIPE process aborts.
	 */
	sigignore(SIGPIPE);

	/*
	 * Allocate the main dispatcher
	 */
	struct mettle *m = mettle();
	if (m == NULL) {
		log_error("could not initialize");
		return 1;
	}

	/*
	 * Check to see if we were injected by metasploit
	 */
	if (strcmp(argv[0], "m") == 0) {
		/*
		 * There is a fd sitting here, trust me
		 */
		mettle_add_tcp_sock(m, (int)((long *)argv)[1]);
	} else {
		/*
		 * Start system logger
		 */
		log_init_file(stderr);
		log_init_flush_thread();

		parse_cmdline(argc, argv, m);
	}

	/*
	 * Start mettle and event loop
	 */
	mettle_start(m);

	mettle_free(m);

	return 0;
}

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

#include "argv_split.h"
#include "log.h"
#include "mettle.h"
#include "service.h"

static void usage(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("  -h, --help             display help\n");
	printf("  -u, --uri <uri>        add connection URI\n");
	printf("  -U, --uuid <uuid>      set the UUID (base64)\n");
	printf("  -d, --debug <level>    enable debug output (set to 0 to disable)\n");
	printf("  -o, --out <file>       write debug output to a file\n");
	printf("  -b, --background <0|1> start as a background service (0 disable, 1 enable)\n");
	printf("  -p, --persist [none|install|uninstall] manage persistence\n");
	printf("  -m, --modules <path>   add modules from path\n");
	printf("  -n, --name <name>      name to start as\n");
	printf("  -l, --listen\n");
	printf("  -c, --console\n");
	printf("\n");
	exit(1);
}

static void start_logger(const char *out)
{
	FILE *l = stderr;
	if (out) {
	      FILE *f = fopen(out, "w");
	      if (f) l = f;
	}
	log_init_file(l);
	log_init_flush_thread();
}

#define PAYLOAD_INJECTED (1 << 0)
static int parse_cmdline(int argc, char * const argv[], struct mettle *m, int flags)
{
	int c = 0;
	int index = 0;

	struct option options[] = {
		{"debug", required_argument, NULL, 'd'},
		{"out", required_argument, NULL, 'o'},
		{"uri", required_argument, NULL, 'u'},
		{"uuid", required_argument, NULL, 'U'},
		{"session-guid", required_argument, NULL, 'G'},
		{"background", required_argument, NULL, 'b'},
		{"persist", required_argument, NULL, 'p'},
		{"name", required_argument, NULL, 'n'},
		{"listen", required_argument, NULL, 'l'},
		{"console", no_argument, NULL, 'c'},
		{"modules", required_argument, NULL, 'm'},
		{ 0, 0, NULL, 0 }
	};
	const char *short_options = "hu:U:G:d:o:b:p:n:lcm:";
	const char *out = NULL;
	char *name = strdup("mettle");
	bool name_flag = false;
	bool debug = false;
	bool background = false;
	bool interactive = false;
	enum persist_type persist = persist_none;
	int log_level = 0;

	/*
	 * This needs to be initialized to 1 in order for consistent behavior from
	 * getopt_long when called multiple times.
	 */
	optind = 1;
	while ((c = getopt_long(argc, argv, short_options, options, &index)) != -1) {
		switch (c) {
		case 'c':
			interactive = true;
			break;
		case 'u':
			c2_add_transport_uri(mettle_get_c2(m), optarg);
			break;
		case 'U':
			mettle_set_uuid_base64(m, optarg);
			break;
		case 'G':
			mettle_set_session_guid_base64(m, optarg);
			break;
		case 'm':
			modulemgr_load_path(mettle_get_modulemgr(m), optarg);
			break;
		case 'n':
			free(name);
			name = strdup(optarg);
			name_flag = true;
			break;
		case 'p':
			if (strcmp("install", optarg) == 0) {
				persist = persist_install;
			} else if (strcmp("uninstall", optarg) == 0) {
				persist = persist_uninstall;
			} else {
				persist = persist_none;
			}
			break;
		case 'd':
			{
				const char *errstr = NULL;
				log_level = strtonum(optarg, 0, 3, &errstr);
				if (errstr != NULL) {
					fprintf(stderr, "invalid debug level '%s': %s\n", optarg, errstr);
					return -1;
				}
				log_set_level(log_level);
				debug = (log_level > 0);
			}
			break;
		case 'b':
			{
				const char *errstr = NULL;
				int val = strtonum(optarg, 0, 1, &errstr);
				if (errstr != NULL) {
					fprintf(stderr, "invalid background setting '%s': %s", optarg, errstr);
					return -1;
				}
				background = val == 1;
			}
			break;
		case 'o':
			out = optarg;
			break;
		case 'h':
		default:
			usage("mettle");
		}
	}

	/*
	 * Only rename if we were not injected, since currently we do not know
	 * where the real argv is. This is fixable, but possibly not useful to
	 * rename an injected process :)
	 */
	if (name_flag && !(flags & PAYLOAD_INJECTED)) {
		log_info("using name: %s", name);
		setproctitle(name);
	}

	if (interactive) {
		mettle_console_start_interactive(m);
		return 0;
	}

	if (debug) {
		start_logger(out);
	}

	if (background) {
		char *args, *new_args;
		if (asprintf(&args, "%s -d %u", argv[0], log_level) == -1) {
			return -1;
		}
		optind = 1;
		while ((c = getopt_long(argc, argv, short_options, options, &index)) != -1) {
			if (c == 'u' || c == 'U' || c == 'o') {
				if (asprintf(&new_args, "%s -%c %s", args, c, optarg) == -1) {
					return -1;
				}
				free(args);
				args = new_args;
			}
		}
		start_service(name, argv[0], args, persist);
		free(args);
	}

	return 0;
}

void parse_default_args(struct mettle *m, int flags)
{
	static char default_opts[] = "DEFAULT_OPTS"
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  ";

	if (strncasecmp(default_opts, "default_opts", strlen("default_opts"))) {
		size_t argc = 0;
		char **argv = NULL;
		argv = argv_split(default_opts, argv, &argc);
		if (argv) {
			parse_cmdline(argc, argv, m, flags);
		}
	}
}

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
static char **saved_argv;
#endif

extern char *__progname;

char *get_progname(char *argv0);

int main(int argc, char * argv[])
{
	int flags = 0;
	__progname = get_progname(argv[0]);

	/*
	 * Disable SIGPIPE process aborts.
	 */
	signal(SIGPIPE, SIG_IGN);

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
		flags |= PAYLOAD_INJECTED;

		/*
		 * There is a fd sitting here, trust me
		 */
		int fd = (int)((long *)argv)[1];
		char *uri;
		if (asprintf(&uri, "fd://%d", fd) > 0) {
			struct c2 *c2 = mettle_get_c2(m);
			c2_add_transport_uri(c2, uri);
			free(uri);
		}
		parse_default_args(m, flags);
	} else {

#ifndef HAVE_SETPROCTITLE
		/* Prepare for later setproctitle emulation */
		saved_argv = calloc(argc + 1, sizeof(*saved_argv));
		for (int i = 0; i < argc; i++) {
			saved_argv[i] = strdup(argv[i]);
		}
		compat_init_setproctitle(argc, argv);
		argv = saved_argv;
#endif

		parse_default_args(m, flags);
		if (parse_cmdline(argc, argv, m, flags)) {
			return -1;
		}
	}

	/*
	 * Start mettle and event loop
	 */
	mettle_start(m);

	mettle_free(m);

	return 0;
}

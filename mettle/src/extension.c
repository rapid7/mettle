/**
 * Copyright 2017 Rapid7
 * @brief extension source file
 * @file extension.c
 */

#include <stdlib.h>
#include <unistd.h>
#include <ev.h>

#include "buffer_queue.h"
#include "extension.h"
#include "process.h"

struct extension {
	struct ev_loop *loop;
	ev_io watcher;

	struct buffer_queue *in_queue;
	struct tlv_dispatcher *td;
};

struct tlv_dispatcher *extension_get_tlv_dispatcher(struct extension *e)
{
	return e->td;
}

static void on_tlv_response(struct tlv_dispatcher *td, void *arg)
{
	struct extension *e = arg;
	void *buf;
	size_t len;
	while((buf = tlv_dispatcher_dequeue_response(td, false, &len))) {
		fwrite(buf, len, 1, stdout);
		free(buf);
	}
	fflush(stdout);
}

static void on_read(EV_P_ ev_io *w, int revents)
{
	unsigned char buf[8192];
	ssize_t n;
	struct extension *e = w->data;

	// Read in raw TLV message data from Mettle.
	while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		buffer_queue_add(e->in_queue, buf, n);
	}

	if (n < 0) {
		// Error condition
	}

	// Process TLV message(s)
	size_t buflen = buffer_queue_len(e->in_queue);
	struct tlv_packet *request = malloc(buflen);
	if (request) {
		buffer_queue_remove(e->in_queue, request, buflen);
		tlv_dispatcher_process_request(e->td, request);
	}
}

static void extension_signal_handler(struct ev_loop *loop,
               ev_signal *w, int revents)
{
	switch (w->signum) {
		case SIGINT:
		case SIGTERM:
			ev_break(loop, EVBREAK_ALL);
			break;
		default:
			break;
       }
}

/*
 * Basic initialization for the extension and return a pointer.
 */
struct extension *extension()
{
	struct extension *e = calloc(1, sizeof(*e));

	if (e == NULL) {
		goto err;
	}

	e->in_queue = buffer_queue_new();

	e->loop = ev_default_loop(EVFLAG_NOENV | EVBACKEND_SELECT);

	process_set_nonblocking_stdio();
	ev_io_init(&e->watcher, on_read, STDIN_FILENO, EV_READ);
	e->watcher.data = e;

	e->td = tlv_dispatcher_new(on_tlv_response, e);
	if (e->td == NULL) {
		goto err;
	}

	ev_io_start(e->loop, &e->watcher);

	return e;

err:
	extension_free(e);
	return NULL;
}


/*
 * Extension logging.
 */
void extension_log_to_mettle(int level)
{
	log_init_file(stderr);
	log_set_level(level);
}

void extension_log_to_file(int level, char const * filename)
{
	log_init(filename);
	log_set_level(level);
}

/*
 * Add/register the TLV handlers of an extension.
 */
int extension_add_handler(struct extension *e,
		uint32_t command_id, tlv_handler_cb cb, void *arg)
{
	if (e == NULL) {
		return -1;
	}

	return tlv_dispatcher_add_handler(e->td, command_id, cb, arg);
}

static void add_command_id(uint32_t command_id, void *arg)
{
	if (command_id == COMMAND_ID_CORE_LOADLIB) {
		return;
	}
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_u32(*p, TLV_TYPE_UINT, command_id);
}

static struct tlv_packet *core_loadlib(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(ctx->td, 0, UINT_MAX, add_command_id, &p);
	return p;
}

/*
 * Start the extension.
 */
int extension_start(struct extension *e)
{
	if (e == NULL) {
		return -1;
	}

	// Register core loadlib so the extension can respond to the command itself
	extension_add_handler(e, COMMAND_ID_CORE_LOADLIB, core_loadlib, NULL);

	// Setup signal handling
	ev_signal sigint_w, sigterm_w;
	ev_signal_init(&sigint_w, extension_signal_handler, SIGINT);
	ev_signal_start(e->loop, &sigint_w);
	ev_signal_init(&sigterm_w, extension_signal_handler, SIGTERM);
	ev_signal_start(e->loop, &sigterm_w);

	// And GO!!!
	ev_run(e->loop, 0);
	return 0;
}

/*
 * Free data objects associated with the extension.
 */
void extension_free(struct extension *e)
{
	if (e) {
		ev_io_stop(e->loop, &e->watcher);
		if (e->td) {
			tlv_dispatcher_free(e->td);
		}
		if (e->in_queue) {
			buffer_queue_free(e->in_queue);
		}
		free(e);
	}
}


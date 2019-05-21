/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <eio.h>
#include <sigar.h>

#include "base64.h"
#include "c2.h"
#include "extensions.h"
#include "log.h"
#include "mettle.h"
#include "process.h"
#include "tlv.h"

#define EV_LOOP_FLAGS  (EVFLAG_NOENV | EVBACKEND_SELECT | EVFLAG_FORKCHECK)

struct mettle {
	struct channelmgr *cm;
	struct extmgr *em;
	struct modulemgr *mm;
	struct procmgr *pm;

	struct c2 *c2;
	struct tlv_dispatcher *td;

	sigar_t *sigar;
	sigar_sys_info_t sysinfo;
	char fqdn[SIGAR_MAXDOMAINNAMELEN];
	struct ev_loop *loop;
	struct ev_timer heartbeat;
};

static struct ev_idle eio_idle_watcher;
static struct ev_async eio_async_watcher;

static void
eio_idle_cb(struct ev_loop *loop, struct ev_idle *w, int revents)
{
	if (eio_poll() != -1) {
		ev_idle_stop(loop, w);
	}
}

static void
eio_async_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	if (eio_poll() == -1) {
		ev_idle_start(loop, &eio_idle_watcher);
	}
	ev_async_start(ev_default_loop(EV_LOOP_FLAGS), &eio_async_watcher);
}

static void
eio_want_poll(void)
{
	ev_async_send(ev_default_loop(EV_LOOP_FLAGS), &eio_async_watcher);
}

static void
eio_done_poll(void)
{
	ev_async_stop(ev_default_loop(EV_LOOP_FLAGS), &eio_async_watcher);
}

static void
heartbeat_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	log_info("Heartbeat");
}

int start_heartbeat(struct mettle *m)
{
	ev_timer_init(&m->heartbeat, heartbeat_cb, 0, 5.0);
	m->heartbeat.data = m;
	ev_timer_start(m->loop, &m->heartbeat);
	return 0;
}

struct c2 * mettle_get_c2(struct mettle *m)
{
	return m->c2;
}

struct modulemgr * mettle_get_modulemgr(struct mettle *m)
{
	return m->mm;
}

struct ev_loop * mettle_get_loop(struct mettle *m)
{
	return m->loop;
}

const char *mettle_get_fqdn(struct mettle *m)
{
	return m->fqdn;
}

const char *mettle_get_machine_id(struct mettle *m)
{
	return m->sysinfo.uuid;
}

int mettle_set_uuid_base64(struct mettle *m, char *uuid_b64)
{
	char *uuid = calloc(1, strlen(uuid_b64));
	if (uuid == NULL)
		return -1;
	int uuid_len = base64decode(uuid, uuid_b64, strlen(uuid_b64));
	tlv_dispatcher_set_uuid(m->td, uuid, uuid_len);
	free(uuid);
	return 0;
}

int mettle_set_session_guid_base64(struct mettle *m, char *guid_b64)
{
	char *guid = calloc(1, strlen(guid_b64));
	if (guid == NULL)
		return -1;
	int guid_len = base64decode(guid, guid_b64, strlen(guid_b64));
	if (guid_len != SESSION_GUID_LEN)
		return -1;
	tlv_dispatcher_set_session_guid(m->td, guid);
	free(guid);
	return 0;
}

struct tlv_dispatcher *mettle_get_tlv_dispatcher(struct mettle *m)
{
	return m->td;
}

sigar_t *mettle_get_sigar(struct mettle *m)
{
	return m->sigar;
}

struct channelmgr * mettle_get_channelmgr(struct mettle *m)
{
	return m->cm;
}

struct extmgr * mettle_get_extmgr(struct mettle *m)
{
	return m->em;
}

struct procmgr * mettle_get_procmgr(struct mettle *m)
{
	return m->pm;
}

void mettle_free(struct mettle *m)
{
	if (m) {
		if (m->pm)
			procmgr_free(m->pm);
		if (m->c2)
			c2_free(m->c2);
		if (m->cm)
			channelmgr_free(m->cm);
		if (m->td)
			tlv_dispatcher_free(m->td);
		free(m);
	}
}

static void mettle_signal_handler(struct ev_loop *loop,
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

static void on_tlv_response(struct tlv_dispatcher *td, void *arg)
{
	struct mettle *m = arg;
	void *buf;
	size_t len;

	while ((buf = tlv_dispatcher_dequeue_response(td, true, &len))) {
		c2_write(m->c2, buf, len);
		free(buf);
	}
}

static void on_c2_event(struct c2 *c2, int event, void *arg)
{
	struct mettle *m = arg;
	if (event & C2_REACHABLE) {
	}
}

static void on_c2_read(struct c2 *c2, void *arg)
{
	struct mettle *m = arg;
	struct buffer_queue *q = c2_ingress_queue(c2);
	struct tlv_packet *request;

	// need td here to pass into the reader
	while ((request = tlv_packet_read_buffer_queue(m->td, q))) {
		tlv_dispatcher_process_request(m->td, request);
	}
}

struct mettle *mettle(void)
{
	struct mettle *m = calloc(1, sizeof(*m));

	if (m == NULL) {
		return NULL;
	}

	/*
	 * TODO: let libev choose the backend instead of demanding select. On Linux
	 * 2.6.22 we get the following with the epoll backend (compiled with much
	 * more recent headers):
	 *
	 * (libev) epoll_wait: Bad file descriptor
	 * Abort
	 */
	m->loop = ev_default_loop(EV_LOOP_FLAGS);

	ev_idle_init(&eio_idle_watcher, eio_idle_cb);
	ev_async_init(&eio_async_watcher, eio_async_cb);
	eio_init(eio_want_poll, eio_done_poll);

	m->c2 = c2_new(m->loop);
	if (m->c2 == NULL) {
		goto err;
	}
	c2_set_cbs(m->c2, on_c2_read, NULL, on_c2_event, m);

	if (sigar_open(&m->sigar) == -1) {
		goto err;
	}

	m->pm = procmgr_new(m->loop);

	procmgr_setup_env();

	m->em = extmgr_new();

	sigar_fqdn_get(m->sigar, m->fqdn, sizeof(m->fqdn));

	sigar_sys_info_get(m->sigar, &m->sysinfo);

	m->td = tlv_dispatcher_new(on_tlv_response, m);
	if (m->td == NULL) {
		goto err;
	}

	m->cm = channelmgr_new(m->td);
	if (m->cm == NULL) {
		goto err;
	}

	m->mm = modulemgr_new(m->loop);
	if (m->mm == NULL) {
		goto err;
	}

	return m;

err:
	mettle_free(m);
	return NULL;
}

int mettle_start(struct mettle *m)
{
	ev_signal sigint_w, sigterm_w;

	ev_signal_init(&sigint_w, mettle_signal_handler, SIGINT);
	ev_signal_start(m->loop, &sigint_w);
	ev_signal_init(&sigterm_w, mettle_signal_handler, SIGTERM);
	ev_signal_start(m->loop, &sigterm_w);

	tlv_register_coreapi(m);

	tlv_register_channelapi(m);

	tlv_register_stdapi(m);

	c2_start(m->c2);

	ev_async_start(m->loop, &eio_async_watcher);

	start_heartbeat(m);

	return ev_run(m->loop, 0);
}

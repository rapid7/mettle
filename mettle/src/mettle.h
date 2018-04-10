/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.h
 */

#ifndef _METTLE_H_
#define _METTLE_H_

#include "c2.h"
#include "channel.h"
#include "module.h"
#include "process.h"

#include <ev.h>
#include <sigar.h>

struct mettle * mettle(void);

int mettle_start(struct mettle *m);

const char *mettle_get_fqdn(struct mettle *m);

const char *mettle_get_machine_id(struct mettle *m);

int mettle_set_uuid_base64(struct mettle *m, char *uuid_b64);

int mettle_set_session_guid_base64(struct mettle *m, char *uuid_b64);

sigar_t *mettle_get_sigar(struct mettle *m);

struct ev_loop * mettle_get_loop(struct mettle *m);

struct tlv_dispatcher *mettle_get_tlv_dispatcher(struct mettle *m);

void mettle_free(struct mettle *);

struct c2 * mettle_get_c2(struct mettle *m);

struct channelmgr * mettle_get_channelmgr(struct mettle *m);

struct extmgr * mettle_get_extmgr(struct mettle *m);

struct procmgr * mettle_get_procmgr(struct mettle *m);

struct modulemgr * mettle_get_modulemgr(struct mettle *m);

void mettle_console_start_interactive(struct mettle *m);

#endif

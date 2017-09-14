/**
 * Copyright 2017 Rapid7
 * @brief extension header file
 * @file extension.h
 */

#ifndef _EXTENSION_H_
#define _EXTENSION_H_

/*
 * Header files that an extension will need to properly operate.
 */
#include <log.h>
#include <pthread.h>
#include <tlv.h>
#include <util.h>

/*
 * Data and function declarations.
 */
struct extension;

struct tlv_dispatcher *extension_get_tlv_dispatcher(struct extension *e);

struct extension *extension();

int extension_add_handler(struct extension *e,
		const char *method, tlv_handler_cb cb, void *arg);

int extension_start(struct extension *e);

void extension_free(struct extension *e);

#endif

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
#include <utils.h>
#include <command_ids.h>

/*
 * Data, function, etc. declarations.
 */
struct extension;

struct tlv_dispatcher *extension_get_tlv_dispatcher(struct extension *e);

struct extension *extension();

#define EXTENSION_LOG_LEVEL_ERROR	0
#define EXTENSION_LOG_LEVEL_DEBUG	1
#define EXTENSION_LOG_LEVEL_INFO	2
void extension_log_to_mettle(int level);

void extension_log_to_file(int level, char const *filename);

int extension_add_handler(struct extension *e,
		uint32_t command_id, tlv_handler_cb cb, void *arg);

int extension_start(struct extension *e);

void extension_free(struct extension *e);

#endif

/**
 * Copyright 2015 Rapid7
 * @brief System Process API
 * @file process.c
 */

#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

struct tlv_packet *sys_process_get_processes(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	/*
	 * Add process iteration here
	 */
	return p;
}

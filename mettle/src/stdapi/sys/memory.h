#ifndef _STDAPI_MEMORY_H
#define _STDAPI_MEMORY_H

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx);
struct addr_range *parse_maps_file(pid_t pid);

#endif

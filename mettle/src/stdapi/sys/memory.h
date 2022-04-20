#ifndef _STDAPI_MEMORY_H
#define _STDAPI_MEMORY_H

struct addr_range
{
    unsigned long start;
    unsigned long end;
    struct addr_range *next;
};

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx);
struct addr_range *parse_maps_file(pid_t pid);
char *search_mem_sections(pid_t pid, unsigned int min_len, struct addr_range *ranges);
char *get_readable_str(FILE *fp, unsigned int min_len, unsigned long *start_addr, unsigned long sect_len);

#endif

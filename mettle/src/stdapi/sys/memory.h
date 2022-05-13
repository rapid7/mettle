#ifndef _STDAPI_MEMORY_H
#define _STDAPI_MEMORY_H

struct addr_range
{
    unsigned long start;
    unsigned long end;
    struct addr_range *next;
};

struct match_result
{
    char *match_str;
    unsigned long section_start;
    unsigned long section_end;
    unsigned long match_offset;
};

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx);
struct addr_range *parse_maps_file(pid_t pid);
char *search_mem_sections(pid_t pid, unsigned int min_len, struct addr_range *ranges, char *needles[], int needle_amt);
char *get_readable_str(FILE *fp, unsigned int min_len, unsigned long *start_addr, unsigned long end_addr);
regmatch_t *find_match(char *str, char *needles[], int needle_amt);
int add_matches(char *full_str, struct match_result **results, unsigned long sect_start, unsigned long sect_end, regmatch_t *matches);

#endif

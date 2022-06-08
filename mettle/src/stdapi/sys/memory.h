#ifndef _STDAPI_MEMORY_H
#define _STDAPI_MEMORY_H

#ifdef __linux__

struct addr_range
{
    unsigned long start;
    unsigned long end;
    struct addr_range *next;
};

struct match_result
{
    char *match_str;
    unsigned long section_len;
    unsigned long section_start;
    unsigned long match_offset;
};

struct needle_info
{
    char *needle;
    regex_t preg;
    unsigned char compiled;
};

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx);
struct addr_range *parse_maps_file(pid_t pid);
struct match_result *search_mem_sections(pid_t pid, unsigned int min_len, struct addr_range *ranges, char *needles[], int needle_amt, int *match_len);
char *get_readable_str(FILE *fp, unsigned int min_len, unsigned long *start_addr, unsigned long end_addr);
regmatch_t *find_matches(char *str, struct needle_info *needle_arr, int needle_amt);
int add_matches(char *full_str, struct match_result **results, unsigned long match_offset, unsigned long sect_start, unsigned long sect_len, regmatch_t *matches);

#endif

#endif

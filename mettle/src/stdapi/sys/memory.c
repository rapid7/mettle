#include <stdio.h>
#include <regex.h>
#include <fnmatch.h>
#include <fnmatch.h>
#include <ctype.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"
#include "command_ids.h"
#include "memory.h"

#define NEEDLES_MAX 5
#define MAX_ADDR_DATA 500
#define MATCH_LEN_MAX 250
#define MATCH_PER_NEEDLE_MAX 5

#define MAX_STRINGS 350
#define MIN_SEARCH_LEN 5

struct tlv_packet *mem_read(struct tlv_handler_ctx *ctx)
{
    unsigned int pid;
    unsigned long size;
    unsigned long start_addr;
    struct tlv_packet *p = NULL;

    if(tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid) == -1)
    {
        log_debug("Pid was not retrieved.\n");
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    if(tlv_packet_get_u64(ctx->req, TLV_TYPE_MEM_SEARCH_START_ADDR, &start_addr) == -1)
    {
        log_debug("Failed to retrieve the start address.\n");
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    if(tlv_packet_get_u64(ctx->req, TLV_META_TYPE_QWORD, &size) == -1)
    {
        log_debug("Failed to retrieve search to search.\n");
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    if(size <= 0)
    {
        size = MATCH_LEN_MAX;
    }

    char pid_str[8];
    sprintf(pid_str, "%d", pid);
    int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/mem") + 1;

    char *read_str = NULL;
    char mem_path[path_len];
    snprintf(mem_path, path_len, "/proc/%s/mem", pid_str);

    FILE *fp = fopen(mem_path, "r");
    if(fp == NULL)
    {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    fseek(fp, start_addr, SEEK_SET);

    fclose(fp);

    return NULL;
}

struct tlv_packet *mem_search(struct tlv_handler_ctx *ctx)
{
    unsigned int pid;
    unsigned int match_len;
    unsigned int min_search_len;
    struct tlv_packet *p = NULL;
    log_debug("Inside mem_search()\n");

    if(tlv_packet_get_u32(ctx->req, TLV_TYPE_PID, &pid) == -1)
    {
        log_debug("Failed to retrieve PID\n");
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    if(tlv_packet_get_u32(ctx->req, TLV_TYPE_MEM_SEARCH_MATCH_LEN, &match_len) == -1)
    {
        log_debug("Failed to retrieve match length\n");
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    if(tlv_packet_get_u32(ctx->req, TLV_TYPE_UINT, &min_search_len) == -1)
    {
        log_debug("Using default minimum for search\n");
        min_search_len = MIN_SEARCH_LEN;
    }

    if(match_len > MATCH_LEN_MAX)
    {
        match_len = MATCH_LEN_MAX;
    }

    struct addr_range *ranges = parse_maps_file(pid);
    if(ranges == NULL)
    {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    struct addr_range *curr_range = ranges;
    while(curr_range->next != NULL)
    {
        curr_range = curr_range->next;
    }

    struct tlv_iterator i = {
        .packet = ctx->req,
        .value_type = TLV_TYPE_MEM_SEARCH_NEEDLE
    };

    char *needle;
    uint8_t needles_len = 0;
    char *needles[ NEEDLES_MAX ];
    while((needle = tlv_packet_iterate_str(&i)))
    {
        needles[ needles_len ] = malloc(strlen(needle) + 1);
        strncpy(needles[ needles_len ], needle, strlen(needle) + 1);
        needles_len++;
    }

    struct match_result *matches = search_mem_sections(pid, min_search_len, ranges, needles, needles_len);
    if(matches == NULL)
    {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    for(uint8_t i = 0; i < needles_len; i++)
    {
        free(needles[i]);
    }

    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

char *get_readable_str(FILE *fp, unsigned int min_len, unsigned long *start_addr, unsigned long end_addr)
{
    int curr_index = 0;
    unsigned int curr_char;
    unsigned long index = 0;
    unsigned int max_str_len = MATCH_LEN_MAX - 1;
    char *printable = malloc(MATCH_LEN_MAX);
    memset(printable, 0, MATCH_LEN_MAX);

    unsigned long sect_len = end_addr - *start_addr;
    while(index < sect_len)
    {
        if((curr_char = fgetc(fp)) == EOF)
        {
            *start_addr += index;
            return NULL;
        }
        if(isprint(curr_char))
        {
            //log_debug("Current char: %c\n", (char) curr_char);
            printable[curr_index] = curr_char;
            curr_index++;
        }
        else
        {
            int str_len = strlen(printable);

            // don't collect strings smaller than min size
            if(str_len < min_len && str_len > 0)
            {
               curr_index = 0;
               memset(printable, 0, str_len);
            }
            else if(str_len > 0)
            {
                *start_addr += index;
                return printable;
            }
        }

        if(curr_index > max_str_len)
        {
            max_str_len += MATCH_LEN_MAX;
            int str_len = strlen(printable);
            int new_len = str_len + MATCH_LEN_MAX;
            printable = realloc(printable, str_len + MATCH_LEN_MAX);
            memset(printable + str_len, 0, MATCH_LEN_MAX);
        }

        index++;
    }

    *start_addr += index;
    if(strlen(printable) == 0)
    {
        return NULL;
    }

    return printable;
}

/*
 * checks a string against one or more compiled regexes and returns those that match
 */
regmatch_t *find_matches(char *str, struct needle_info *needle_arr, int needle_amt)
{
    int exec_ret;
    int num_matches = 0;
    regmatch_t reg_matches[needle_amt * MATCH_PER_NEEDLE_MAX];

    int match_index = 0;
    regmatch_t *matches = malloc(sizeof(regmatch_t) * (needle_amt * MATCH_PER_NEEDLE_MAX));
    for(int i = 0; i < needle_amt; i++)
    {
        // make sure that the regex is a compiled regex
        if(needle_arr[i].compiled == 1)
        {
            exec_ret = regexec(&needle_arr[i].preg, str, MATCH_PER_NEEDLE_MAX, &reg_matches[i * MATCH_PER_NEEDLE_MAX], 0);
            if(exec_ret == 0)
            {
                memcpy(matches + match_index, &reg_matches[i * MATCH_PER_NEEDLE_MAX], sizeof(regmatch_t) * MATCH_PER_NEEDLE_MAX);
                num_matches++;
                match_index += MATCH_PER_NEEDLE_MAX;
            }
        }
    }

    if(num_matches == 0)
    {
        return NULL;
    }

    return matches;
}

struct match_result *search_mem_sections(pid_t pid, unsigned int min_len, struct addr_range *ranges, char *needles[], int needle_amt)
{
    char pid_str[8];
    sprintf(pid_str, "%d", pid);
    int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/mem") + 1;

    char *read_str = NULL;
    char mem_path[path_len];
    snprintf(mem_path, path_len, "/proc/%s/mem", pid_str);

    struct addr_range *current = NULL, *first = NULL;
    FILE *fp = fopen(mem_path, "r");
    if(fp == NULL)
    {
        return NULL;
    }

    int res_size = 0;
    regmatch_t *matches;
    current = first = ranges;

    struct match_result *results = malloc(sizeof(struct match_result) * needle_amt * MATCH_PER_NEEDLE_MAX);
    struct match_result *first_res = results;
    memset(results, 0, sizeof(struct match_result) * needle_amt * MATCH_PER_NEEDLE_MAX);

    if(results == NULL)
    {
        fclose(fp);
        return NULL;
    }

    // compile a version of each needle to test against each string
    regex_t regex_arr[needle_amt];
    struct needle_info needle_arr[needle_amt];
    for(int i = 0; i < needle_amt; i++)
    {
        needle_arr[i].needle = needles[i];
        if(regcomp(&needle_arr[i].preg, needles[i], REG_EXTENDED) != 0)
        {
            needle_arr[i].compiled = 0;
        }
        else
        {
            needle_arr[i].compiled = 1;
        }
    }

    unsigned long curr_addr = current->start;
    while(current->next != NULL)
    {
        fseek(fp, curr_addr, SEEK_SET);

        read_str = get_readable_str(fp, min_len, &curr_addr, current->end);
        if(read_str == NULL)
        {
            current = current->next;
            curr_addr = current->start;
            continue;
        }
        else if((matches = find_matches(read_str, needle_arr, needle_amt)) != NULL)
        {
            int match_num = add_matches(read_str, results, current->start, current->end, matches);
            log_debug("Number of matches: %d\n", match_num);
            res_size += match_num;
        }

        free(read_str);
        if(curr_addr >= current->end)
        {
            current = current->next;
            curr_addr = current->start;
        }
    }

    fclose(fp);
    for(int j = 0; j < needle_amt; j++)
    {
        regfree(&needle_arr[j].preg);
    }

    if(res_size == 0)
    {
        return NULL;
    }

    return first_res;
}

int add_matches(char *full_str, struct match_result *results, unsigned long sect_start, unsigned long sect_end, regmatch_t *matches)
{
    int index = 0;
    regmatch_t *prev = NULL;
    regmatch_t *start = matches;

    do
    {
        log_debug("Start offset of match: %lu\n", start->rm_so);
        log_debug("End offset of match: %lu\n", start->rm_eo);
        if(start->rm_so != start->rm_eo)
        {
          log_debug("In start\n");
          int match_len = start->rm_eo - start->rm_so + 1;
          log_debug("Got match_len\n");
          results->match_str = malloc(match_len);
          log_debug("Performed malloc()\n");
          if(results->match_str == NULL)
          {
              log_debug("Allocation for match_str failed");
              prev = start;
              start++;
              free(prev);
              continue;
          }

          /*
           * save the start and end addresses of memory location match was found in
           * save the offset of the match, and save the matched string
           */
          strncpy(results->match_str, full_str + start->rm_so, match_len);
          results->section_start = sect_start;
          results->section_end = sect_end;
          results->match_offset = sect_start + start->rm_so;
          log_debug("Match saved: %s\n", results->match_str);
          results++;
          index++;
        }

        prev = start;
        start++;
        free(prev);
    } while(start != NULL);

    return index;
}

/*
 *  This will open /proc/PID/maps and search for
 *  the start and end addresses for all readable sections
 *  that are not file-backed
 */
struct addr_range *parse_maps_file(pid_t pid)
{
    char pid_str[8];
    sprintf(pid_str, "%d", pid);
    int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/maps") + 1;

    char maps_path[path_len];
    snprintf(maps_path, path_len, "/proc/%s/maps", pid_str);

    FILE *fp = fopen(maps_path, "r");
    if(fp == NULL)
    {
        //log_debug("Could not open maps file.\n");
        return NULL;
    }

    regex_t regex;
    int index = 0;
    char *line = malloc(MAX_ADDR_DATA);
    struct addr_range *first = NULL, *current = NULL;
    regcomp(&regex, "rw[x|-][p|-]", REG_EXTENDED | REG_NOSUB);
    while(fgets(line, MAX_ADDR_DATA, fp) != NULL)
    {
        int len = strlen(line);
        if(regexec(&regex, line, 0, NULL, 0) == 0)
        {
            char *addr_begin = strtok(line, "-");
            char *addr_end = strtok(NULL, "- ");
            struct addr_range *range = malloc(sizeof(struct addr_range));
            range->start = strtoul(addr_begin, NULL, 16);
            range->end = strtoul(addr_end, NULL, 16);

            if(index == 0)
            {
                first = current = range;
                first->next = NULL;
            }
            else
            {
                current->next = range;
                current = range;
                current->next = NULL;

                if(index == 1)
                {
                    first->next = current;
                }
            }

            index++;
        }

        memset(line, 0, MAX_ADDR_DATA);
    }

    fclose(fp);
    free(line);
    regfree(&regex);

    return first;
}

void sys_memory_register_handlers(struct mettle *m)
{
    struct channelmgr *cm = mettle_get_channelmgr(m);
    struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

    tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_SYS_PROCESS_MEM_SEARCH, mem_search, m);
}

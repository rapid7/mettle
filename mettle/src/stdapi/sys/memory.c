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
        log_debug("Current needle: %s\n", needle);
        needles_len++;
    }

    char *strs = search_mem_sections(pid, min_search_len, ranges, needles, needles_len);
    if(strs == NULL)
    {
        return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }

    for(uint8_t i = 0; i < needles_len; i++)
    {
        free(needles[i]);
    }

    return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

char *get_readable_str(FILE *fp, unsigned int min_len, unsigned long *start_addr, unsigned long sect_len)
{
    int index = 0;
    int curr_index = 0;
    unsigned int curr_char;
    char *printable = malloc(MATCH_LEN_MAX);
    memset(printable, 0, MATCH_LEN_MAX);

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

        if(curr_index > MATCH_LEN_MAX - 1)
        {
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

regmatch_t *find_match(char *str, char *needles[], int needle_amt)
{
    int exec_ret;
    int compile_ret;
    regex_t regex_arr[needle_amt];
    regmatch_t *reg_matches = malloc(sizeof(regmatch_t) * needle_amt);

    for(int i = 0; i < needle_amt; i++)
    {
        compile_ret = regcomp(&regex_arr[i], needles[i], REG_EXTENDED);
        if(compile_ret)
        {
            log_debug("%s is an invalid regex\n", needles[i]);
            memset(&reg_matches[i], 0, sizeof(regmatch_t));
            continue;
        }

        regexec(&regex_arr[i], str, needle_amt + 1, &reg_matches[i], 0);
    }

    return reg_matches;
}

char *search_mem_sections(pid_t pid, unsigned int min_len, struct addr_range *ranges, char *needles[], int needle_amt)
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

    regmatch_t *matches;
    unsigned long index = 0;
    current = first = ranges;

    unsigned long sect_len = current->end - current->start;
    while(current->next != NULL)
    {
        fseek(fp, current->start, SEEK_SET);

        log_debug("Reading string at: %lu\n", current->start);
        read_str = get_readable_str(fp, min_len, &current->start, sect_len);
        if(read_str == NULL)
        {
            current = current->next;
            continue;
        }
        else if((matches = find_match(read_str, needles, needle_amt)) != NULL)
        {
            // add to *existing* match data
            log_debug("Stuff");
        }

        log_debug("Current string: %s, length: %ld\n", read_str, strlen(read_str));
        free(read_str);

        if(current->start >= current->end)
        {
            log_debug("Moving to next address range\n");
            current = current->next;
            sect_len = current->end - current->start;
        }
    }

    fclose(fp);
    return NULL;
}

/*
 *  This will open /proc/PID/maps and search for
 *  the start and end addresses for all readable sections
 */
struct addr_range *parse_maps_file(pid_t pid)
{
    char pid_str[8];
    sprintf(pid_str, "%d", pid);
    int path_len = strlen("/proc/") + strlen(pid_str) + strlen("/maps") + 1;

    char maps_path[path_len];
    snprintf(maps_path, path_len, "/proc/%s/maps", pid_str);
    log_debug("Opening maps file: %s\n", maps_path);

    FILE *fp = fopen(maps_path, "r");
    if(fp == NULL)
    {
        log_debug("Could not open maps file.\n");
        return NULL;
    }

    regex_t regex;
    int index = 0;
    char *line = malloc(MAX_ADDR_DATA);
    struct addr_range *first = NULL, *current = NULL;
    regcomp(&regex, "r[w|-][x|-][p|-]", REG_EXTENDED | REG_NOSUB);
    while(fgets(line, MAX_ADDR_DATA, fp) != NULL)
    {
        int len = strlen(line);
        if(regexec(&regex, line, 0, NULL, 0) == 0 && (line[len - 2] == ' ' || line[len - 2] == ']'))
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

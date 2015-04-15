#ifndef _METTLE_H_
#define _METTLE_H_

#include "zlog.h"
#define mettle_log(format, ...) zlog_time(ZLOG_LOC, format "\n", ##__VA_ARGS__)
#define mettle_log_init(log_file) zlog_init(log_file)
#define mettle_log_init_file(file_hdl) zlog_init_file(file_hdl)
#define mettle_log_init_flush_thread zlog_init_flush_thread
#define mettle_log_finish zlog_finish
#define mettle_log_flush_buffer zlog_flush_buffer

struct mettle;

struct mettle *mettle_open(void);

int mettle_start(struct mettle *m);

void mettle_close(struct mettle *);

#endif

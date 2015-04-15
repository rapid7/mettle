#ifndef ZLOG_H_
# define ZLOG_H_

#define ZLOG_LOC __FILE__, __LINE__

#include <stdio.h>

// Start API

// initialize zlog: flush to a log file
void zlog_init(char const* log_file);
// initialize zlog: flush to file handle
void zlog_init_file(FILE *out);
// creating a flushing thread
void zlog_init_flush_thread();
// finish using the zlog; clean up
void zlog_finish();
// explicitely flush the buffer in memory
void zlog_flush_buffer();

// log an entry; using the printf format
void zlogf(char const * fmt, ...);

// log an entry with a timestamp
void zlogf_time(char const * fmt, ...);

// log an entry with the filename and location;
//   the first 2 arguments can be replaced by ZLOG_LOC which
//   will be filled by the compiler
void zlog(char* filename, int line, char const * fmt, ...);

// log an entry with the filename and location with a timestamp
void zlog_time(char* filename, int line, char const * fmt, ...);

// End API

#endif

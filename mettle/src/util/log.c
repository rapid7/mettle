/*
 * Zlog utility
 * Written by Zhiqiang Ma http://www.ericzma.com
 * Released under Unlicense (Public Domain)
 * https://github.com/zma/zlog
 */

#include <libgen.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <util/log.h>

// --------------------------------------------------------------
FILE* zlog_fout = NULL;

char _zlog_buffer[LOG_BUFFER_SIZE][LOG_BUFFER_STR_MAX_LEN];
int _zlog_buffer_size = 0;

pthread_mutex_t _zlog_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
// --------------------------------------------------------------

static inline void _zlog_buffer_lock()
{
    pthread_mutex_lock(&_zlog_buffer_mutex);
}

static inline void _zlog_buffer_unlock()
{
    pthread_mutex_unlock(&_zlog_buffer_mutex);
}

static void _zlog_flush_buffer()
{
    int i = 0;
    for (i = 0; i < _zlog_buffer_size; i++) {
        fprintf(zlog_fout, "%s", _zlog_buffer[i]);
    }
    fflush(zlog_fout);
    _zlog_buffer_size = 0;
}

// first zlog_get_buffer, write to @return
// then zlog_finish_buffer
//
// zlog_get_buffer may flush the buffer, which require I/O ops
static inline char* zlog_get_buffer()
{
    _zlog_buffer_lock();
    if (_zlog_buffer_size == LOG_BUFFER_SIZE) {
        _zlog_flush_buffer();
    }

    // allocate buffer
    _zlog_buffer_size++;
    return _zlog_buffer[_zlog_buffer_size-1];
}

static inline void zlog_finish_buffer()
{
#ifdef LOG_FORCE_FLUSH_BUFFER
    _zlog_flush_buffer();
#endif
    _zlog_buffer_unlock();
}

// --------------------------------------------------------------

void zlog_init(char const* log_file)
{
    zlog_fout = fopen(log_file, "a+");
}

void zlog_init_file(FILE *out)
{
    zlog_fout = out;
}

void* zlog_buffer_flush_thread(void* arg)
{
    struct timeval tv;
    time_t lasttime;
    time_t curtime;

    gettimeofday(&tv, NULL);

    lasttime = tv.tv_sec;

    do {
        sleep(LOG_SLEEP_TIME_SEC);
        gettimeofday(&tv, NULL);
        curtime = tv.tv_sec;
        if ( (curtime - lasttime) >= LOG_FLUSH_INTERVAL_SEC ) {
            zlog_flush_buffer();
            lasttime = curtime;
        } else {
            _zlog_buffer_lock();
            if (_zlog_buffer_size >= LOG_BUFFER_FLUSH_SIZE ) {
                _zlog_flush_buffer();
            }
            _zlog_buffer_unlock();
        }
    } while (1);
    return NULL;
}

void zlog_init_flush_thread()
{
    pthread_t thr;
    pthread_create(&thr, NULL, zlog_buffer_flush_thread, NULL);
}

void zlog_flush_buffer()
{
    _zlog_buffer_lock();
    _zlog_flush_buffer();
    _zlog_buffer_unlock();
}

void zlog_finish()
{
    zlog_flush_buffer();
    if (zlog_fout != stdout) {
        fclose(zlog_fout);
    }
    zlog_fout = stdout;
}

void zlog_time(char* filename, int line, char const * fmt, ...)
{
    static char timebuf[LOG_BUFFER_STR_MAX_LEN];
    struct timeval tv;
    time_t curtime;
    char* buffer = NULL;

    va_list va;

    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	strftime(timebuf, LOG_BUFFER_STR_MAX_LEN, "%m-%d-%Y %T",
	    localtime(&curtime));
    buffer = zlog_get_buffer();
	snprintf(buffer, LOG_BUFFER_STR_MAX_LEN, "[%s.%02lds] [%s:%d] ", timebuf,
	    (unsigned long)tv.tv_usec, basename(filename), line);
    buffer += strlen(buffer); // print at most 5 digit of line

    va_start(va, fmt);
    vsnprintf(buffer, LOG_BUFFER_STR_MAX_LEN, fmt, va);
    zlog_finish_buffer();
    va_end(va);
}

void zlog(char* filename, int line, char const * fmt, ...)
{
    char* buffer = NULL;
    va_list va;

    buffer = zlog_get_buffer();
    snprintf(buffer, LOG_BUFFER_STR_MAX_LEN, "[%s:%d]", filename, line);
    va_start(va, fmt);
    vsnprintf(buffer, LOG_BUFFER_STR_MAX_LEN, fmt, va);
    zlog_finish_buffer();
    va_end(va);
}

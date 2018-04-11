/*
 * Zlog utility
 * Written by Zhiqiang Ma http://www.ericzma.com
 * Released under Unlicense (Public Domain)
 * https://github.com/zma/zlog
 */

#include <ctype.h>
#include <libgen.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "log.h"

static FILE *zlog_fout = NULL;
void (*zlog_cb)(const char *buf) = NULL;

static char _zlog_buffer[LOG_BUFFER_SIZE][LOG_BUFFER_STR_MAX_LEN];
static int _zlog_buffer_size = 0;
int _zlog_level = 0;

static pthread_mutex_t _zlog_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	if (zlog_fout != NULL) {
		for (int i = 0; i < _zlog_buffer_size; i++) {
			fprintf(zlog_fout, "%s", _zlog_buffer[i]);
		}
		fflush(zlog_fout);
	}
	if (zlog_cb != NULL) {
		for (int i = 0; i < _zlog_buffer_size; i++) {
			_zlog_buffer[i][strlen(_zlog_buffer[i]) - 1] = '\0';
			zlog_cb(_zlog_buffer[i]);
		}
	}
	_zlog_buffer_size = 0;
}

/*
 * first zlog_get_buffer, write to @return
 * then zlog_finish_buffer
 *
 * zlog_get_buffer may flush the buffer, which require I/O ops
 */
static inline char *zlog_get_buffer()
{
	_zlog_buffer_lock();
	if (_zlog_buffer_size == LOG_BUFFER_SIZE) {
		_zlog_flush_buffer();
	}

	/*
	 * allocate buffer
	 */
	_zlog_buffer_size++;
	return _zlog_buffer[_zlog_buffer_size - 1];
}

static inline void zlog_finish_buffer()
{
#ifdef LOG_FORCE_FLUSH_BUFFER
	_zlog_flush_buffer();
#endif
	_zlog_buffer_unlock();
}

void zlog_init(char const *log_file)
{
	zlog_fout = fopen(log_file, "a+");
}

void zlog_init_file(FILE * out)
{
	zlog_fout = out;
}

void zlog_init_cb(void (*cb)(const char *msg))
{
	zlog_cb = cb;
}

void *zlog_buffer_flush_thread(void *arg)
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
		if ((curtime - lasttime) >= LOG_FLUSH_INTERVAL_SEC) {
			zlog_flush_buffer();
			lasttime = curtime;
		} else {
			_zlog_buffer_lock();
			if (_zlog_buffer_size >= LOG_BUFFER_FLUSH_SIZE) {
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

static const char *short_filename(const char *filename)
{
	char *src = strstr(filename, "src/");
	if (src) {
		src += strlen("src/");
	}
	return src;
}

void zlog_time(const char *filename, int line, char const *fmt, ...)
{
	va_list va;
	char *buffer = NULL;
	char timebuf[64];
	char usecbuf[16];
	struct timeval tv;
	time_t curtime;

	if (zlog_fout || zlog_cb) {
		gettimeofday(&tv, NULL);
		curtime = tv.tv_sec;
		strftime(timebuf, 64, "%m-%d-%Y %H:%M:%S", localtime(&curtime));
		snprintf(usecbuf, 16, "%.03f", tv.tv_usec / 1000000.0);

		buffer = zlog_get_buffer();
		snprintf(buffer, LOG_BUFFER_STR_MAX_LEN, "[%s%ss] [%s:%d] ",
			timebuf, usecbuf + 1, short_filename(filename), line);
		buffer += strlen(buffer);

		va_start(va, fmt);
		vsnprintf(buffer, LOG_BUFFER_STR_MAX_LEN, fmt, va);
		zlog_finish_buffer();
		va_end(va);
	}
}

void zlog(const char *filename, int line, char const *fmt, ...)
{
	va_list va;
	char *buffer = NULL;

	if (zlog_fout || zlog_cb) {
		buffer = zlog_get_buffer();
		snprintf(buffer, LOG_BUFFER_STR_MAX_LEN, "[%s:%d]",
			short_filename(filename), line);
		va_start(va, fmt);
		vsnprintf(buffer, LOG_BUFFER_STR_MAX_LEN, fmt, va);
		zlog_finish_buffer();
		va_end(va);
	}
}

/*
 * hex dump from http://sws.dett.de/mini/hexdump-c/
 */
void zlog_hex(const char *filename, int line, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	unsigned char c;
	char bytestr[4] = { 0 };
	char addrstr[10] = { 0 };
	char hexstr[16 * 3 + 5] = { 0 };
	char charstr[16 * 1 + 5] = { 0 };

	for (size_t n = 1; n <= len; n++) {

		if (n % 16 == 1) {
			/*
			 * store address for this line
			 */
			snprintf(addrstr, sizeof(addrstr), "0x%02x",
				(int)((size_t) p - (size_t) buf));
		}

		c = *p;
		if (!isprint(c)) {
			c = '.';
		}

		/*
		 * store hex str (for left side)
		 */
		snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

		/*
		 * store char str (for right side)
		 */
		snprintf(bytestr, sizeof(bytestr), "%c", c);
		strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

		if (n % 16 == 0) {
			/*
			 * line completed
			 */
			zlog_time(filename, line, "[%4.4s]   %-50.50s  %s\n", addrstr,
				hexstr, charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if (n % 8 == 0) {
			/*
			 * half line: add whitespaces
			 */
			strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
			strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
		}
		p++;
	}

	if (strlen(hexstr) > 0) {
		/*
		 * print rest of buffer if not empty
		 */
		zlog_time(filename, line, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr,
			charstr);
	}
}

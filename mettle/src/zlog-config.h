#ifndef ZLOG_CONFIG_H_
# define ZLOG_CONFIG_H_

// #define ZLOG_DISABLE_LOG 1
#define ZLOG_BUFFER_STR_MAX_LEN 128
#define ZLOG_BUFFER_SIZE (0x1 << 22)
#define ZLOG_REAL_WORLD_TIME 1

// only for debug, enabling this will slow down the log
// #define ZLOG_FORCE_FLUSH_BUFFER

#define ZLOG_FLUSH_INTERVAL_SEC 1
#define ZLOG_SLEEP_TIME_SEC 1
// In practice: flush size < .8 * BUFFER_SIZE
#define ZLOG_BUFFER_FLUSH_SIZE (0.8 * ZLOG_BUFFER_SIZE)

#endif

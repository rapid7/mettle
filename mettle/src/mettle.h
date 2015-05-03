#ifndef _METTLE_H_
#define _METTLE_H_

struct mettle;

struct mettle *mettle(void);

int mettle_start(struct mettle *m);

void mettle_free(struct mettle *);

int mettle_add_server_uri(struct mettle *m, const char *uri);

#endif

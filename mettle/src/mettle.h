#ifndef _METTLE_H_
#define _METTLE_H_

struct mettle;

struct mettle *mettle_open(void);

int mettle_start(struct mettle *m);

void mettle_close(struct mettle *);

#endif

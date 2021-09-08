/**
 * Copyright 2015 Rapid7
 * @brief Miscelaneous system functions
 * @file utils.h
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/socket.h>

/*
 * COUNT_OF from Google Chromium, deals with C++ objects
 */
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/*
 * Determines min/max in a typesafe and side effect-free way
 */
#define TYPESAFE_MAX(a, b) \
   ({ __typeof__(a) _a = (a); \
		  __typeof__(b) _b = (b); \
		  _a > _b ? _a : _b; })

#define TYPESAFE_MIN(a, b) \
   ({ __typeof__(a) _a = (a); \
		  __typeof__(b) _b = (b); \
		  _a < _b ? _a : _b; })

int make_socket_nonblocking(int fd);

char *
parse_sockaddr(struct sockaddr_storage *addr, uint16_t *port);

#endif

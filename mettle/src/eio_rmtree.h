#ifndef _EIO_RMTREE_H_
#define _EIO_RMTREE_H_

#include <eio.h>

eio_req *
eio_rmtree(const char *path, int pri, eio_cb cb, void *data);

#ifdef _WIN32
  #if !defined(S_ISLNK)
    #define S_ISLNK(mode) (0)
  #endif
#endif

#endif
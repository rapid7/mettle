AM_CPPFLAGS = -I$(top_srcdir)/include/compat
AM_CPPFLAGS += -I$(top_srcdir)/src
AM_CPPFLAGS += -DLIBEXTENSION

lib_LTLIBRARIES = libextension.la

libextension_la_LIBADD = -lev
libextension_la_LIBADD += -lpthread

libextension_la_SOURCES = extension.c
libextension_la_SOURCES += ../../src/buffer_queue.c
libextension_la_SOURCES += ../../src/log.c
libextension_la_SOURCES += ../../src/tlv.c

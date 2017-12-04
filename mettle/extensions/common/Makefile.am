AM_CPPFLAGS = -I$(top_srcdir)/include/compat
AM_CPPFLAGS += -I$(top_srcdir)/src
AM_CPPFLAGS += -DLIBEXTENSION

lib_LTLIBRARIES = libextension.la

libextension_la_LIBADD = -lev
libextension_la_LIBADD += -lpthread
libextension_la_LIBADD += -lmettle

libextension_la_SOURCES = extension.c

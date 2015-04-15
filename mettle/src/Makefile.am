AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libmettle.la

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += zlog.c

bin_PROGRAMS = mettle

mettle_SOURCES = main.c
mettle_LDADD = libmettle.la -luv
mettle_LDADD += $(METTLE_LDADD)
mettle_LDADD += $(PLATFORM_LDADD)
mettle_LDFLAGS = $(PLATFORM_LDFLAGS)

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libmettle.la

libmettle_la_LIBADD = -luv
libmettle_la_LIBADD += -lcurl
libmettle_la_LIBADD += -ltls

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += log.c
libmettle_la_SOURCES += network_client.c

if !HAVE_REALLOCARRAY
libmettle_la_SOURCES += compat/reallocarray.c
endif

if !HAVE_STRTONUM
libmettle_la_SOURCES += compat/strtonum.c
endif

bin_PROGRAMS = mettle

mettle_SOURCES = main.c
mettle_LDADD = libmettle.la
mettle_LDADD += $(METTLE_LDADD)
mettle_LDADD += $(PLATFORM_LDADD)
mettle_LDFLAGS = $(PLATFORM_LDFLAGS)

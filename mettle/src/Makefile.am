AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libmettle.la

libmettle_la_LIBADD = -luv
libmettle_la_LIBADD += -lcurl
libmettle_la_LIBADD += -ldnet
libmettle_la_LIBADD += -lsigar
#libmettle_la_LIBADD += -ltls

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += buffer_queue.c
libmettle_la_SOURCES += channel.c
libmettle_la_SOURCES += log.c
libmettle_la_SOURCES += network_client.c
libmettle_la_SOURCES += tlv.c
libmettle_la_SOURCES += tlv_coreapi.c
libmettle_la_SOURCES += stdapi/stdapi.c

if !HAVE_REALLOCARRAY
libmettle_la_SOURCES += compat/reallocarray.c
endif

if !HAVE_STRTONUM
libmettle_la_SOURCES += compat/strtonum.c
endif

if !HAVE_STRLCAT
libmettle_la_SOURCES += compat/strlcat.c
endif

if !HAVE_STRLCPY
libmettle_la_SOURCES += compat/strlcpy.c
endif

bin_PROGRAMS = mettle

mettle_SOURCES = main.c
mettle_LDADD = libmettle.la

mettle_LDFLAGS = -static --static -pie

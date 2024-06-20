AM_CPPFLAGS = -I$(top_srcdir)/include/compat
AM_CPPFLAGS += -I$(top_srcdir)/../util

lib_LTLIBRARIES = libmettle.la

libmettle_la_LIBADD = -ldnet
libmettle_la_LIBADD += -lcurl
libmettle_la_LIBADD += -leio
libmettle_la_LIBADD += -lev
libmettle_la_LIBADD += -ljson-c
libmettle_la_LIBADD += -lpthread
libmettle_la_LIBADD += -lsigar
libmettle_la_LIBADD += -lz

if HAVE_REFLECT
libmettle_la_LIBADD += -lreflect
endif

libmettle_la_SOURCES = mettle.c
libmettle_la_SOURCES += argv_split.c
libmettle_la_SOURCES += base64.c
libmettle_la_SOURCES += bufferev.c
libmettle_la_SOURCES += buffer_queue.c
libmettle_la_SOURCES += c2.c
libmettle_la_SOURCES += c2_http.c
libmettle_la_SOURCES += c2_tcp.c
libmettle_la_SOURCES += channel.c
libmettle_la_SOURCES += coreapi.c
libmettle_la_SOURCES += crypttlv.c
libmettle_la_SOURCES += mtwister.c
libmettle_la_SOURCES += mbedtls_ext.c
libmettle_la_SOURCES += eio_rmtree.c
libmettle_la_SOURCES += extension.c
libmettle_la_SOURCES += extensions.c
libmettle_la_SOURCES += http_client.c
libmettle_la_SOURCES += json.c
libmettle_la_SOURCES += log.c
libmettle_la_SOURCES += md5.c
libmettle_la_SOURCES += module.c
libmettle_la_SOURCES += mettle_rpc.c
libmettle_la_SOURCES += network_client.c
libmettle_la_SOURCES += network_server.c
libmettle_la_SOURCES += ringbuf.c
libmettle_la_SOURCES += sha1.c
libmettle_la_SOURCES += tlv.c
libmettle_la_SOURCES += stdapi/stdapi.c
if HOST_WIN
libmettle_la_SOURCES += console-unsupported.c
libmettle_la_SOURCES += inet_ntop.c inet_pton.c
libmettle_la_SOURCES += posix_win.c
libmettle_la_SOURCES += process_win.c
libmettle_la_SOURCES += service_win.c
else
libmettle_la_SOURCES += console.c linenoise.c
libmettle_la_SOURCES += process.c
libmettle_la_SOURCES += service.c
libmettle_la_LIBADD += -lutil
endif
libmettle_la_SOURCES += utils.c
if HOST_APPLE
libmettle_la_SOURCES += stdapi/webcam/apple_webcam.m
libmettle_la_SOURCES += stdapi/audio/apple_output.m
libmettle_la_SOURCES += stdapi/audio/posix_output.c
libmettle_la_SOURCES += stdapi/clipboard/apple_clipboard.m
libmettle_la_SOURCES += stdapi/sys/posix_process.c
endif
if HOST_OSX
libmettle_la_SOURCES += stdapi/ui/osx_desktop.m
libmettle_la_SOURCES += stdapi/ui/osx_keyboard.m
libmettle_la_SOURCES += stdapi/ui/osx_mouse.m
libmettle_la_SOURCES += stdapi/audio/apple_mic.m
libmettle_la_SOURCES += stdapi/sys/posix_process.c
endif
if HOST_LINUX
libmettle_la_SOURCES += stdapi/audio/linux_mic.c
libmettle_la_SOURCES += stdapi/webcam/linux_webcam.c
libmettle_la_SOURCES += stdapi/audio/linux_output.c
libmettle_la_SOURCES += stdapi/audio/posix_output.c
libmettle_la_SOURCES += stdapi/sys/posix_process.c
endif

libmettle_la_SOURCES += compat/progname.c

if HOST_IOS
libmettle_la_SOURCES += compat/glob.c
endif

if !HAVE_REALLOCARRAY
libmettle_la_SOURCES += compat/reallocarray.c
endif

if !HAVE_SETPROCTITLE
libmettle_la_SOURCES += compat/setproctitle.c
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
mettle_LDFLAGS = $(PLATFORM_LDADD)

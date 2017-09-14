bin_PROGRAMS = sniffer

sniffer_LDADD = -ldnet
sniffer_LDADD += -lextension
sniffer_LDADD += -lpcap
sniffer_SOURCES = sniffer.c
sniffer_SOURCES += ../../src/ringbuf.c

sniffer_CFLAGS = -I$(top_srcdir)/extensions
sniffer_CFLAGS += -I$(top_srcdir)/src
sniffer_LDFLAGS = $(PLATFORM_LDADD)

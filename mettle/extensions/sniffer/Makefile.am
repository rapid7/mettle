if !HOST_WIN
bin_PROGRAMS = sniffer
endif

sniffer_LDADD = -ldnet
sniffer_LDADD += -lmettle
sniffer_LDADD += -lpcap
sniffer_SOURCES = sniffer.c

sniffer_CFLAGS = -I$(top_srcdir)/src
sniffer_LDFLAGS = $(PLATFORM_LDADD)

if MAKEBIN
install-exec-hook:
	$(top_builddir)/../../tools/elf2bin $(bindir)/$(bin_PROGRAMS) $(bindir)/$(bin_PROGRAMS).bin
endif

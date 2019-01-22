if !HOST_WIN
bin_PROGRAMS = sniffer
endif

sniffer_LDADD = -ldnet
sniffer_LDADD += -lpcap
sniffer_LDADD += $(abs_top_builddir)/src/libmettle.la
sniffer_SOURCES = sniffer.c

sniffer_CFLAGS = -I$(top_srcdir)/src
sniffer_LDFLAGS = $(PLATFORM_LDADD)

if MAKEBIN
install-exec-hook:
	elf2bin $(bindir)/$(bin_PROGRAMS) $(bindir)/$(bin_PROGRAMS).bin
endif

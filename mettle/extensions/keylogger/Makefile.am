if HOST_OSX

AM_CPPFLAGS = -I$(top_srcdir)/src

lib_LTLIBRARIES = libswift2mettle.la

libswift2mettle_la_LIBADD = -lmettle
libswift2mettle_la_SOURCES = swift2mettle.c

CLEANFILES = keylogger

keylogger: CallBackFunctions.swift Keylogger.swift main.swift
	swiftc -v -L $(abs_top_builddir)/../lib/ -I $(top_srcdir)/extensions/keylogger -target x86_64-apple-macosx10.13 $^ -o $@
	cp $@ $(bindir)/

install-exec-hook: keylogger

else

bin_PROGRAMS = keylogger

keylogger_LDADD = -lmettle
keylogger_LDADD += -ldnet
keylogger_SOURCES = keylogger.c
keylogger_CFLAGS = -I$(top_srcdir)/src
keylogger_LDFLAGS = $(PLATFORM_LDADD)

if MAKEBIN
install-exec-hook:
	$(top_builddir)/../../tools/elf2bin $(bindir)/$(bin_PROGRAMS) $(bindir)/$(bin_PROGRAMS).bin
endif

endif


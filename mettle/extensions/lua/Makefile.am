if !HOST_WIN
bin_PROGRAMS = lua
endif

lua_LDADD = -llua
lua_LDADD += $(abs_top_builddir)/src/libmettle.la
lua_SOURCES = lua.c

lua_CFLAGS = -I$(top_srcdir)/src
lua_LDFLAGS = $(PLATFORM_LDADD)

if MAKEBIN
install-exec-hook:
	$(top_builddir)/../../tools/elf2bin $(bindir)/$(bin_PROGRAMS) $(bindir)/$(bin_PROGRAMS).bin
endif

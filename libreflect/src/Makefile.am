AM_CPPFLAGS = -I../include

# AM_CPPFLAGS += -DDEBUG

lib_LTLIBRARIES = libreflect.la

libreflect_la_SOURCES = map_elf.c
libreflect_la_SOURCES += stack_setup.c

if HAVE_ASM
AM_CPPFLAGS += -I$(top_srcdir)/arch/$(HOST_OS)/$(HOST_CPU)
libreflect_la_SOURCES += jump.c
libreflect_la_SOURCES += exec.c
endif

if HOST_LINUX
libreflect_la_SOURCES += memfd_exec.c
endif

AM_CPPFLAGS = -I$(top_builddir)/include

bin_PROGRAMS = noexec

noexec_SOURCES = noexec.c
noexec_LDADD = $(abs_top_builddir)/src/libreflect.la

noexec_LDFLAGS = -static --static-pie

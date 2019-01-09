AM_CPPFLAGS = -I$(abs_top_srcdir)/include

if COMPILE_EXAMPLES
bin_PROGRAMS = noexec

noexec_SOURCES = noexec.c
noexec_LDADD = $(abs_top_builddir)/src/libreflect.la

noexec_LDFLAGS = -static $(STATIC_PIE)
endif

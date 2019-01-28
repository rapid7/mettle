AM_CPPFLAGS = -I../include

bin_PROGRAMS =

if HAVE_STATIC_PIE
if HAVE_ASM
bin_PROGRAMS += noexec

noexec_SOURCES = noexec.c
noexec_LDADD = $(abs_top_builddir)/src/libreflect.la

noexec_LDFLAGS = -static $(STATIC_PIE)
endif
endif

if HOST_LINUX
bin_PROGRAMS += memfd_exec

memfd_exec_SOURCES = memfd_exec.c
memfd_exec_LDADD = $(abs_top_builddir)/src/libreflect.la

memfd_exec_LDFLAGS = -static
endif

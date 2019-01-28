AC_INIT([libreflect], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([../mettle/m4])
AM_MAINTAINER_MODE([enable])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT

case $host_os in
	*linux*)
		HOST_OS=linux
		CPPFLAGS="$CPPFLAGS -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE"
esac

AM_CONDITIONAL([HOST_LINUX], [test x$HOST_OS = xlinux])
AC_SUBST([HOST_OS], [$HOST_OS])
AC_SUBST([HOST_CPU], [$host_cpu])

dnl Check that we have assembly to do the thing
AC_CHECK_HEADER([$srcdir/arch/$HOST_OS/$HOST_CPU/arch_jump.h], [
			HAVE_ASM=1
			], [
			HAVE_ASM=0
			AC_MSG_WARN([cannot find assembly for $HOST_OS-$HOST_CPU, falling back to memfd_create/execveat])])

AM_CONDITIONAL([HAVE_ASM], [test x$HAVE_ASM = x1])
AC_SUBST([HAVE_ASM], [$HAVE_ASM])

dnl TODO: add checks for non-Linux ELF-based systems that use headers other
dnl than <link.h> for macros similar to, but named differently from, ElfW(X)

dnl We'll need these shared checks when we start doing fancier stuff
dnl CHECK_LIBC_COMPAT
dnl CHECK_PROGNAME

dnl TODO: add checks that the resulting binaries are actually static PIEs
AX_CHECK_LINK_FLAG([--static-pie], [
			dnl --static-pie was added in GCC 8
			STATIC_PIE=--static-pie
			], [
			AX_CHECK_LINK_FLAG([--static --pie], [
					dnl The mettle toolchain has extra magic to allow --static and --pie
					dnl to work together. Accepted, but produces incorrect behavior in
					dnl GCC 8. That case is caught by the preceding check.
					STATIC_PIE="--static --pie"
					], [
					AC_MSG_WARN([cannot build static PIEs, skipping noexec example])
					]
)])

AM_CONDITIONAL([HAVE_STATIC_PIE], [test "x$STATIC_PIE" != "x"])
AC_SUBST([STATIC_PIE], [$STATIC_PIE])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	examples/Makefile
	include/reflect.h
])

CFLAGS="$CFLAGS -Wall -Werror -pedantic -std=gnu99"
CFLAGS="$CFLAGS -DBUILD_TUPLE=\\\"$TARGET\\\""

AC_OUTPUT

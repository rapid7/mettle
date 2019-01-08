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

AM_CONDITIONAL([HOST_LINUX],   [test x$HOST_OS = xlinux])
AC_SUBST([HOST_OS], [$HOST_OS])
AC_SUBST([HOST_CPU], [$host_cpu])

dnl TODO: add checks for non-Linux ELF-based systems that use headers other
dnl than <link.h> for macros similar to, but named differently from, ElfW(X)

dnl We'll need these shared checks when we start doing fancier stuff
dnl CHECK_LIBC_COMPAT
dnl CHECK_PROGNAME

CFLAGS="$CFLAGS -Wall -Werror -pedantic -std=gnu99"
CFLAGS="$CFLAGS -DBUILD_TUPLE=\\\"$TARGET\\\""

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	examples/Makefile
])

dnl TODO: add checks for building static PIEs when building the examples
dnl AC_ARG_ENABLE([staticpie],
dnl 	AS_HELP_STRING([--enable-staticpie], [Building Static PIE]))
dnl AS_IF([test "x$enable_staticpie" = "xyes"], [
dnl 		AC_SUBST([PLATFORM_LDADD], ['-static --static -pie'])
dnl 		AM_CONDITIONAL([MAKEBIN],  [true])
dnl         ], [
dnl 		AM_CONDITIONAL([MAKEBIN],  [false])
dnl ])

AC_OUTPUT

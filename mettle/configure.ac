AC_INIT([mettle], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE([enable])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT

case $host_os in
	*linux*)
		CPPFLAGS="$CPPFLAGS -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE"
		;;
	*mingw*)
		HOST_OS=win
		CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE -D_POSIX -D_POSIX_SOURCE -D__USE_MINGW_ANSI_STDIO"
		CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_POSIX_THREAD_SAFE_FUNCTIONS"
		CPPFLAGS="$CPPFLAGS -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0501"
		CFLAGS="$CFLAGS -static-libgcc"
		LDFLAGS="$LDFLAGS -static-libgcc"
		AC_SUBST([PLATFORM_LDADD], ['-lws2_32 -lwinpthread -static --static'])
		;;
esac

AM_CONDITIONAL([HOST_WIN],     [test x$HOST_OS = xwin])

CHECK_LIBC_COMPAT

CFLAGS="$CFLAGS -Wall -Werror -std=gnu99 -fno-strict-aliasing -Wno-unused-variable -Wno-unused-function"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_ARG_ENABLE([staticpie],
	AS_HELP_STRING([--enable-staticpie], [Building Static PIE]))
AS_IF([test "x$enable_staticpie" = "xyes"], [
	AC_SUBST([PLATFORM_LDADD], ['-static --static -pie'])
])

AC_OUTPUT

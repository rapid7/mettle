AC_INIT([mettle], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT

CFLAGS="$CFLAGS -Wall -std=gnu99 -Werror"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT

AC_PREREQ(2.68)
AC_COPYRIGHT([Copyright (c) 2019 UPLEX - Nils Goroll Systemoptimierung])
AC_INIT([libvmod-file], [trunk], [varnish-support@uplex.de], [vmod-file])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(src/vmod_file.vcc)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], []))
AM_CONDITIONAL(HAVE_RST2MAN, [test "x$RST2MAN" != "xno"])

AC_ARG_WITH([lcov],
	AS_HELP_STRING(
		[--with-lcov=PATH],
		[Location of lcov to generate coverage data (auto)]),
	[LCOV="$withval"],
	AC_CHECK_PROGS(LCOV, [lcov], []))
AM_CONDITIONAL(HAVE_LCOV, [test -n "$LCOV"])

AC_ARG_WITH([genhtml],
	AS_HELP_STRING(
		[--with-genhtml=PATH],
		[Location of genhtml to generate coverage reports (auto)]),
	[GENHTML="$withval"],
	AC_CHECK_PROGS(GENHTML, [genhtml], []))
AM_CONDITIONAL(HAVE_GENHTML, [test -n "$GENHTML"])

m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_PREREQ([6.3.0])
VARNISH_VMODS([file])

VMOD_TESTS="$(cd $srcdir/src && echo tests/*.vtc)"
AC_SUBST(VMOD_TESTS)

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish])

# Checks for C sources
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([munmap])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_HEADERS([fcntl.h])
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_TYPE_SIZE_T

# --enable-stack-protector
AC_ARG_ENABLE(stack-protector,
	AS_HELP_STRING([--enable-stack-protector],[enable stack protector (default is YES)]),
	[],
	[enable_stack_protector=yes])

if test "x$enable_stack_protector" != "xno"; then
	AX_CHECK_COMPILE_FLAG([-fstack-protector],
		AX_CHECK_LINK_FLAG([-fstack-protector],
			[CFLAGS="${CFLAGS} -fstack-protector"], [], []),
		[], [])
fi

# --enable-debugging
AC_ARG_ENABLE(debugging,
	AS_HELP_STRING([--enable-debugging],[enable debugging (default is NO)]),
	[],
	[enable_debugging=no])

# AC_PROG_CC sets CFLAGS to '-g -O2' unless already set, so there's no
# need to add -g. Disable or change by explicitly setting CFLAGS. If
# this option is enabled, then -Og or -O0 becomes the last
# optimization option, and hence takes precedence.
if test "x$enable_debugging" != "xno"; then
	CFLAGS="${CFLAGS} -fno-inline"
	AX_CHECK_COMPILE_FLAG([-Og],
		[CFLAGS="${CFLAGS} -O0 -Og"],
		[CFLAGS="${CFLAGS} -O0"],
		[])
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

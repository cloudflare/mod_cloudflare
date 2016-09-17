dnl Process this file with autoconf to produce a configure script.

AC_INIT([mod_cloudflare],
  [2016.8.0],
  [help@cloudflare.com], [],
  [https://www.cloudflare.com/resources-downloads/])

AC_CONFIG_SRCDIR([mod_cloudflare.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([
  foreign
])
AM_PROG_AR
AC_PROG_LIBTOOL

AC_CHECK_FUNCS([strrchr])

# Checks for apxs.
AC_ARG_WITH([apxs],
  [AC_HELP_STRING([--with-apxs=PATH], [apxs path [default=yes]])],
  [APXS_PATH="$withval"],
  [APXS_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"]
)
AC_PATH_PROG([APXS], [apxs], [no], [${APXS_PATH}])
AS_IF([test "x${APXS}" = "xno"], [AC_MSG_ERROR([apxs not found])],
  [test "x${APXS}" = "x"], [AC_MSG_ERROR([apxs not found])]
)
APXS_CFLAGS=`${APXS} -q CFLAGS 2> /dev/null`
APXS_CPPFLAGS=`${APXS} -q CPPFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR 2> /dev/null`
APXS_INCLUDEDIR=`${APXS} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"

# Checks for apr.
AC_ARG_WITH([apr],
  [AC_HELP_STRING([--with-apr=PATH], [apr config path [default=yes]])],
  [APR_CONFIG="$withval"],
  [with_apr=yes]
)
AC_MSG_CHECKING([whether apr])
AS_IF([test "x$with_apr" != "xno"], [
  AS_IF([test ! -x "${APR_CONFIG}" -o -z "${APR_CONFIG}"], [
    APR_PATH=`${APXS} -q APR_BINDIR 2> /dev/null`
    APR_CONFIG="${APR_PATH}/apr-1-config"
    AS_IF([test ! -x "${APR_CONFIG}"], [
      APR_CONFIG="${APR_PATH}/apr-config"
    ])
  ])
  APR_INCLUDES=`${APR_CONFIG} --includes 2> /dev/null`
  APR_CFLAGS=`${APR_CONFIG} --cflags 2> /dev/null`
  APR_CPPFLAGS=`${APR_CONFIG} --cppflags 2> /dev/null`
  APR_LDFLAGS=`${APR_CONFIG} --ldflags 2> /dev/null`
  APR_LIBS=`${APR_CONFIG} --libs 2> /dev/null`
  AC_MSG_RESULT([yes])
], [
  AC_MSG_ERROR([apr not found])
])

# Apache libraries.
APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES} ${LIBSASS_INCLUDES}"
APACHE_CFLAGS="${APXS_CFLAGS} ${APR_CFLAGS} ${LIBSASS_CPFLAGS}"
APACHE_CPPFLAGS="${APXS_CPPFLAGS} ${APR_CPPFLAGS} ${LIBSASS_CPPFLAGS}"
APACHE_LDFLAGS="${APXS_LDFLAGS} ${APR_LDFLAGS} ${LIBSASS_LDFLAGS}"
APACHE_LIBS="${APXS_LIBS} ${APR_LIBS} ${LIBSASS_LIBS}"
AC_SUBST([APACHE_MODULEDIR])
AC_SUBST([APACHE_INCLUDES])
AC_SUBST([APACHE_CFLAGS])
AC_SUBST([APACHE_CPPFLAGS])
AC_SUBST([APACHE_LDFLAGS])
AC_SUBST([APACHE_LIBS])

AC_CONFIG_FILES([
  Makefile
])
AC_OUTPUT

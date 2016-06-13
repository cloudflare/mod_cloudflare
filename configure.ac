dnl Process this file with autoconf to produce a configure script.

AC_INIT(mod_cloudflare, m4_esyscmd([ ( VERSFILE="./VERSION"; if [ -d .git -a -x "$(which git)" -a -n "$(git describe --tags --always --dirty=-dev 2> /dev/null)" ]; then echo "$(git describe --tags --always --dirty=-dev 2> /dev/null )"; else if [ -f "$VERSFILE" ]; then . "$VERSFILE"; echo "${MAJOR}.${MINOR}.${BUILD}"; else echo "0.0.0"; fi; fi ) | tr -d '\n' ]))
AC_CONFIG_SRCDIR([mod_cloudflare.c])
AC_PREREQ([2.53])

AC_CHECK_FUNCS([strrchr])

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                   [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

AC_SUBST(APXS)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_INCLUDEDIR="`${APXS} -q INCLUDEDIR`"
if test -x ${HTTPD}; then
    HTTPD_VERSION=`${HTTPD} -v | awk '/version/ {print $3}' \
     | awk -F/ '{print $2}'`
else
    if test -f ${HTTPD_INCLUDEDIR}/ap_release.h; then
        HTTPD_VERSION=`grep '^#define AP_SERVER_MAJORVERSION_NUMBER ' \
         ${HTTPD_INCLUDEDIR}/ap_release.h | sed -e \
         's/^#define AP_SERVER_MAJORVERSION_NUMBER \([0-9]\).*/\1.X/'`
    else
        if test -f ${HTTPD_INCLUDEDIR}/httpd.h; then
            HTTPD_VERSION=`grep '^#define APACHE_RELEASE ' \
             ${HTTPD_INCLUDEDIR}/httpd.h | sed -e \
             's/^#define APACHE_RELEASE \([0-9]\).*/\1.X/'`
        else
            HTTPD_VERSION="2.?"
        fi
    fi
fi
AC_MSG_RESULT($HTTPD_VERSION)

CPPFLAGS="${CPPFLAGS}"
CFLAGS=""
LDFLAGS="${LDFLAGS}"
LDLIBS="${LDLIBS}"

AC_SUBST(CPPFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | sed -e 's/\..*//'`

AC_OUTPUT([Makefile])

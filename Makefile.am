ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = EasyApache

moddir = $(prefix)/@APACHE_MODULEDIR@

mod_LTLIBRARIES = mod_cloudflare.la

mod_cloudflare_la_SOURCES = mod_cloudflare.c

mod_cloudflare_la_CFLAGS = @APACHE_CFLAGS@ @APACHE_INCLUDES@
mod_cloudflare_la_CPPFLAGS = @APACHE_CPPFLAGS@ @APACHE_INCLUDES@
mod_cloudflare_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@
mod_cloudflare_la_LIBS = @APACHE_LIBS@

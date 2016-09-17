#!/bin/sh

aclocal
libtoolize --copy
autoheader
automake --add-missing --copy --foreign
autoconf

#!/usr/bin/env bash

#test_debian.sh foo.deb

set -x

# install package with no apache2
zypper --non-interactive install $1
if [ $? -eq 0 ]; then
	echo "NOTE: rpm succeeded despite no apache2. Deps are broken"
fi

# install package with apache2
zypper --non-interactive update
zypper --non-interactive install httpd
zypper --non-interactive install $1
if [ $? -gt 0 ]; then
	echo "rpm failed on install"
	exit 1
fi


#check files/confs in the right place
if [ ! -e /usr/lib64/apache2/mod_cloudflare.so -a ! -e /usr/lib64/apache2/mod_cloudflare.so ]; then
	echo "Module installed incorrectly."
	exit 1
fi
if [ ! -e /etc/apache2/mod_cloudflare.conf ]; then
	echo "Module installed incorrectly."
	exit 1
fi
grep mod_cloudflare.conf /etc/sysconfig/apache2
if [ $? -gt 0 ]; then
	echo "Module installed incorrectly."
	exit 1
fi

#add localhost to conf
sed -i -e 's#\(CloudFlareRemoteIPTrustedProxy.*\)$#\1 127.0.0.1#' /etc/apache2/mod_cloudflare.conf
#localhost curl w/ header
/etc/init.d/apache restart
curl -4 -H"CF-Connecting-IP: 1.2.3.4" localhost:80
sleep 1
grep '1.2.3.4' /var/log/apache2/access_log
if [ $? -gt 0 ]; then
	echo "Log replacement not working"
	exit 1
fi

#delete package
zypper --non-interactive el mod_cloudflare
if [ $? -gt 0 ]; then
	echo "rpm returned fail on remove"
	exit 1
fi

#check files no longer there
if [ -e /usr/lib64/apache2/mod_cloudflare.so -o -e /usr/lib64/apache2/mod_cloudflare.so -o -e /etc/apache2/mod_cloudflare.conf ]; then
	echo "Module uninstalled incorrectly."
	exit 1
fi
grep mod_cloudflare.conf /etc/sysconfig/apache2
if [ $? -gt 0 ]; then
	echo "Module uninstalled incorrectly."
	exit 1
fi

echo "Tests Passed!! OK!"


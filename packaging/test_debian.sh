#!/usr/bin/env bash

# install package
dpkg -i -y $1 
if [ $? -gt 0 ] then
	echo "DPKG failed on install"
	exit 1
fi
#check files/confs in the right place
if [ -e /usr/lib/apache2/modules/mod_cloudflare.so 
	-a -e /etc/apache2/mod-available/cloudflare.conf 
	-a -e /etc/apache2/mod-available/cloudflare.load 
	-a -e /etc/apache2/mod-enabled/cloudflare.conf 
	-a -e /etc/apache2/mod-enabled/cloudflare.load ] then
else
	echo "Module installed incorrectly."
	exit 1
fi

#add localhost to conf
sed -i bck -e 's#\(CloudFlareRemoteIPTrustedProxy.*\)$#\1 127.0.0.1#' /etc/apache2/mod-available/cloudflare.conf
#localhost curl w/ header
/etc/init.d/apache restart
curl -H"CF-Connecting-IP: 1.2.3.4" localhost:80
grep '1.2.3.4' /var/log/apache/access.log
if [ $? -gt 0 ] then
	echo "Log replacement not working"
	exit 1
fi

#delete package
dpkg -r -y $1 
if [ $? -gt 0 ] then
	echo "DPKG returned fail on remove"
fi

#check files no longer there
if [ -e /usr/lib/apache2/modules/mod_cloudflare.so 
	-a -e /etc/apache2/mod-available/cloudflare.conf 
	-a -e /etc/apache2/mod-available/cloudflare.load 
	-a -e /etc/apache2/mod-enabled/cloudflare.conf 
	-a -e /etc/apache2/mod-enabled/cloudflare.load ] then
	echo "Module uninstalled incorrectly."
	exit 1
fi


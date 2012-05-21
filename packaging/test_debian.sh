#!/usr/bin/env bash

#test_debian.sh foo.deb

set -x

# install package with no apache2
sudo dpkg -i $1
if [ $? -eq 0 ]; then
	echo "NOTE: DPKG succeeded despite no apache2. Deps are broken"
fi
# cleanup failed install
sudo dpkg -r libapache2-mod-cloudflare

# install package with apache2
sudo apt-get -y update
sudo apt-get -y install apache2
sudo dpkg -i $1
if [ $? -gt 0 ]; then
	echo "DPKG failed on install"
	exit 1
fi


#check files/confs in the right place
if [ ! -e /usr/lib/apache2/modules/mod_cloudflare.so -a ! -e /etc/apache2/mods-available/cloudflare.conf -a ! -e /etc/apache2/mods-available/cloudflare.load -a ! -e /etc/apache2/mods-enabled/cloudflare.conf -a ! -e /etc/apache2/mods-enabled/cloudflare.load ]; then
	echo "Module installed incorrectly."
	exit 1
fi

#add localhost to conf
sudo sed -i -e 's#\(CloudFlareRemoteIPTrustedProxy.*\)$#\1 127.0.0.1#' /etc/apache2/mods-available/cloudflare.conf
#localhost curl w/ header
sudo /etc/init.d/apache2 restart
curl -4 -H"CF-Connecting-IP: 1.2.3.4" localhost:80
sleep 1
grep '1.2.3.4' /var/log/apache2/access.log
if [ $? -gt 0 ]; then
	echo "Log replacement not working"
	exit 1
fi

#delete package
sudo dpkg -r libapache2-mod-cloudflare
if [ $? -gt 0 ]; then
	echo "DPKG returned fail on remove"
fi

#check files no longer there
if [ -e /usr/lib/apache2/modules/mod_cloudflare.so -a -e /etc/apache2/mods-available/cloudflare.conf -a -e /etc/apache2/mods-available/cloudflare.load -a -e /etc/apache2/mods-enabled/cloudflare.conf -a -e /etc/apache2/mods-enabled/cloudflare.load ]; then
	echo "Module uninstalled incorrectly."
	exit 1
fi

echo "Tests Passed!! OK!"


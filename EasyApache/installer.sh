#!/bin/bash
# Location where to install on cPanel server
CPANEL_DIR="/var/cpanel/easy/apache/custom_opt_mods"

if [ ! -d "$CPANEL_DIR" ]; then
	echo "$CPANEL_DIR not found. This script should only be used on servers that have cPanel installed."
	exit
fi

# Download & tar mod_cloudflare.c
mkdir mod_cloudflare && cd mod_cloudflare && wget "http://www.cloudflare.com/static/misc/mod_cloudflare/mod_cloudflare.c" && cd ..
tar -cvzf $CPANEL_DIR/Cpanel/Easy/ModCloudflare.pm.tar.gz mod_cloudflare/mod_cloudflare.c
# Download ModCloudflare.pm into cPanel directory
wget -P $CPANEL_DIR/Cpanel/Easy/ wget https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/EasyApache/ModCloudflare.pm
# Remove leftover files
rm -rf mod_cloudflare/

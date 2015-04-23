#!/bin/bash -e
# Location where to install on cPanel server
CPANEL_DIR="/var/cpanel/easy/apache/custom_opt_mods"
INSTALL_DIR="$CPANEL_DIR/Cpanel/Easy"

if [ ! -d "$CPANEL_DIR" ]; then
	echo "$CPANEL_DIR not found. This script should only be used on servers that have cPanel installed."
	exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
	mkdir -p "$INSTALL_DIR"
fi

# Download & tar mod_cloudflare.c
mkdir mod_cloudflare && cd mod_cloudflare && wget "https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/mod_cloudflare.c" && cd ..
tar -cvzf $INSTALL_DIR/ModCloudflare.pm.tar.gz mod_cloudflare/mod_cloudflare.c
# Download ModCloudflare.pm into cPanel directory
wget -O $INSTALL_DIR/ModCloudflare.pm https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/EasyApache/ModCloudflare.pm
# Remove leftover files
rm -rf mod_cloudflare/

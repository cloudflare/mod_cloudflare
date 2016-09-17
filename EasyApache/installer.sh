#!/bin/bash

set -e  # exit on errors
set -u  # disallow usage of unset variables
set -o pipefail
trap 'exit 1' ERR

#
# Install mod_cloudflare for EasyApache 3
#
function install_ea3 {

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
   mkdir mod_cloudflare
   # Remove temporary file at exit
   trap 'rm -rf $INSTALL_DIR/mod_cloudflare' 0
   wget -O "$INSTALL_DIR/mod_cloudflare/mod_cloudflare.c" "https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/mod_cloudflare.c"
   tar --directory="$INSTALL_DIR" -cvzf "ModCloudflare.pm.tar.gz" mod_cloudflare

   # Download ModCloudflare.pm into cPanel directory
   wget -O "$INSTALL_DIR/ModCloudflare.pm" "https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/EasyApache/ModCloudflare.pm"

   echo "Done. Please restart EasyApache 3"
}

#
# Install mod_cloudflare for EasyApache 4
#
function install_ea4 {

    #
    # Reasonably reliable way to get OS distribution name and version
    #
    DISTRO_NAME="$(sed -n 's/^NAME="\(.*\)"$/\1/p' /etc/os-release)"
    DISTRO_VERSION="$(sed -n 's/^VERSION_ID="\(.*\)"$/\1/p' /etc/os-release)"

    # Remove trailing minor version
    DISTRO_VERSION="${DISTRO_VERSION%%.*}"

    if [ "$DISTRO_VERSION" -ge 6 ]; then
        printf "\n%s '%s %s'\n" \
            'Installing mod_cloudflare for EasyApache 4 on' "$DISTRO_NAME" "$DISTRO_VERSION"
    else
        echo "ERROR - Your distribution '$DISTRO_NAME $DISTRO_VERSION' is not supported" >&2
        exit 1
    fi

    #
    # Location of the vanilla RPM packages. We'll have to extract certain files and
    # put them where EasyApache 4 wants them.
    #
    DOWNLOAD_URL="https://www.cloudflare.com/static/misc/mod_cloudflare/centos/mod_cloudflare-el$DISTRO_VERSION-x86_64.latest.rpm"

    # Make sure that the directories we want exist
    if [ ! -d "/etc/apache2/conf.d" ]; then
        echo "ERROR - missing /etc/apache2/conf.d, is EasyApache 4 installed?" >&2
        exit 1
    fi
    if [ ! -d "/usr/lib64/apache2/modules" ]; then
        echo "ERROR - missing /usr/lib64/apache2/modules, is EasyApache 4 installed?" >&2
        exit 1
    fi

    # Create temporary file
    RPMFILE="$(mktemp /tmp/mod_cloudflare.rpm.XXXXXXXXXX)"
    # Cleanup at exit.
    trap 'rm -f $RPMFILE' 0

    # Download the correct RPM package
    # echo "Fetching mod_cloudflare..."
    # echo "curl -o /tmp/mod_cloudflare.rpm $DOWNLOAD_URL 2>/dev/null";
    curl -o "$RPMFILE" "$DOWNLOAD_URL" 2>/dev/null

    # Extract the mod_cloudflare config file, fix up the path to where EasyApache 4
    # installs modules, and write it out to the config dir
    # echo "Installing /etc/apache2/conf.d/cloudflare.conf"
    rpm2cpio "$RPMFILE" |
        cpio --to-stdout -i ./etc/httpd/conf.d/cloudflare.conf 2>/dev/null | sed 's/httpd/apache2/' >/etc/apache2/conf.d/cloudflare.conf 2>/dev/null

    # Extract the mod_cloudflare module binary file and put it where EasyApache 4 wants it
    # echo "Installing /usr/lib64/apache2/modules/mod_cloudflare.so"
    rpm2cpio "$RPMFILE" |
        cpio --to-stdout -i ./usr/lib64/httpd/modules/mod_cloudflare.so >/usr/lib64/apache2/modules/mod_cloudflare.so 2>/dev/null

    printf "\nDone. Please restart EasyApache 4\n\n"
}

#
# Main
#
if [ ! -x '/usr/local/cpanel/cpanel' ]; then
    echo "ERROR - cannot find /usr/local/cpanel/cpanel" >&2
    exit 1
fi

#
# Check which version of cPanel we have
#
CPANEL_VERSION="$(/usr/local/cpanel/cpanel -V | sed 's/\..*$//')"

# Version 58 and up have Easy Apache 4
if [ "$CPANEL_VERSION" -gt 57 ]; then
   install_ea4
else
   install_ea3
fi

exit 0

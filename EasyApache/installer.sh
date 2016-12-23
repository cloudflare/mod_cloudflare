#!/bin/bash -e

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
   mkdir mod_cloudflare && cd mod_cloudflare && wget "https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/mod_cloudflare.c" && cd ..
   tar -cvzf $INSTALL_DIR/ModCloudflare.pm.tar.gz mod_cloudflare/mod_cloudflare.c

   # Download ModCloudflare.pm into cPanel directory
   wget -O $INSTALL_DIR/ModCloudflare.pm https://raw.githubusercontent.com/cloudflare/mod_cloudflare/master/EasyApache/ModCloudflare.pm

   # Remove leftover files
   rm -rf mod_cloudflare/
   echo "Done. Please restart EasyApache 3"
   exit
   
}

#
# Install mod_cloudflare for EasyApache 4
#
function install_ea4 {

    #
    # Get OS version from redhat-release
    #
    DISTRO_NAME=`cat /etc/redhat-release | awk {'print$1'}`
    DISTRO_VERSION=`cat /etc/redhat-release | sed -e 's/.*release \(.*\) (.*)/\1/' -e 's/\..*//'`


    if [[ $DISTRO_VERSION == "6" || $DISTRO_VERSION == "7" ]]; then
    echo
        echo "Installing mod_cloudflare for EasyApache 4 on '$DISTRO_NAME $DISTRO_VERSION'"
    else
        echo "ERROR - Your distribution '$DISTRO_NAME $DISTRO_VERSION' is not supported"
        exit
    fi

    #
    # Location of the vanilla RPM packages. We'll have to extract certain files and
    # put them where EasyApache 4 wants them.
    #
    DOWNLOAD_URL="https://www.cloudflare.com/static/misc/mod_cloudflare/centos/mod_cloudflare-el$DISTRO_VERSION-x86_64.latest.rpm"

    # Make sure that the directories we want exist
    if [ ! -d "/etc/apache2/conf.d" ]; then
        echo "ERROR - missing /etc/apache2/conf.d, is EasyApache 4 installed?"
        exit;
    fi
    if [ ! -d "/usr/lib64/apache2/modules" ]; then
        echo "ERROR - missing /usr/lib64/apache2/modules, is EasyApache 4 installed?"
        exit;
    fi

    # Download the correct RPM package
    # echo "Fetching mod_cloudflare..."
    # echo "curl -o /tmp/mod_cloudflare.rpm $DOWNLOAD_URL 2>/dev/null";
    curl -o /tmp/mod_cloudflare.rpm $DOWNLOAD_URL 2>/dev/null;

    # Extract the mod_cloudflare config file, fix up the path to where EasyApache 4
    # installs modules, and write it out to the config dir
    # echo "Installing /etc/apache2/conf.d/cloudflare.conf"
    rpm2cpio /tmp/mod_cloudflare.rpm | cpio --to-stdout -iv ./etc/httpd/conf.d/cloudflare.conf 2>/dev/null | sed 's/httpd/apache2/' >/etc/apache2/conf.d/cloudflare.conf 2>/dev/null

    # Extract the mod_cloudflare module binary file and put it where EasyApache 4 wants it
    # echo "Installing /usr/lib64/apache2/modules/mod_cloudflare.so"
    rpm2cpio /tmp/mod_cloudflare.rpm | cpio --to-stdout -iv ./usr/lib64/httpd/modules/mod_cloudflare.so >/usr/lib64/apache2/modules/mod_cloudflare.so 2>/dev/null

    # Cleanup
    rm /tmp/mod_cloudflare.rpm

    echo
    echo "Done. Please restart EasyApache 4"
    echo
    exit
}

#
# Main
#

# Check if Easy Apache 4 is enabled
if [ -e "/etc/cpanel/ea4/is_ea4" ]; then
   install_ea4
else
   install_ea3
fi


# mod_cloudflare for Apache #
Copyright CloudFlare Inc. 2016

## mod_cloudflare.c ##

Based on mod_remoteip.c, this Apache extension will replace the remote_ip variable in user's logs with the correct remote IP sent from CloudFlare. The module only performs the IP substitution for requests originating from CloudFlare IPs by default.

In addition to this, the extension will also set the HTTPS environment variable to "on" in cases where Flexible SSL is in use. This prevents software such as WordPress from being broken by Flexible SSL.

To install, either run apxs2 directly against the .c source file:

    $ apxs2 -a -i -c mod_cloudflare.c

An alternative way to install is to use GNU autotools, which requires that autoconf and automake already be installed:

    $ autoconf
    $ ./configure
    $ make
    $ make install

No further configuration is needed. However, if you wish to override the default values, the following directives are exposed:

### CloudFlareRemoteIPHeader ###

This specifies the header which contains the original IP. Default:

    CloudFlareRemoteIPHeader CF-Connecting-IP

### CloudFlareRemoteIPTrustedProxy ###

This is to add additional trusted IP addresses or ranges from which we will allow `CloudFlareRemoteIPHeader` to be used from. We will rewrite remote IPs and the SSL variable (in the case of Flexible SSL) from these trusted IPs, additionally `DenyAllButCloudflare` will not deny requests from IPs listed here. See [here][1] for a complete list.

### DenyAllButCloudFlare ###

When this is set, we will deny requests from IPs which aren't in the `CloudFlareRemoteIPTrustedProxy` directive or are not from a Cloudflare IP.

Note that by default, `DenyAllButCloudflare` will not allow Remote IPs, they will need to be whitelisted through `CloudFlareRemoteIPTrustedProxy`.

## Loading the Module ##

Note that on some systems, you may have to add a `LoadModule` directive manually. This should look like:

    LoadModule cloudflare_module /usr/lib/apache2/modules/mod_cloudflare.so

Replace `/usr/lib/apache2/modules/mod_cloudflare.so` with the path to `mod_cloudflare.so` on your system.

## Installing apxs/apxs2 ##

If you cannot find `apxs` or `apxs2`, install `apache2-dev` on Debian and Ubuntu, or `httpd-devel` on Red Hat and CentOS:

    $ apt-get install apache2-dev
    $ yum install httpd-devel

## Additional Notes ##

- If mod\_cloudflare and mod\_remoteip are enabled on the same web server, the server will crash if they both try to set the remote IP to a different value.
- Enabling mod\_cloudflare will not effect the performance of Apache in any noticeable manner. AB testing both over LAN and WAN show no equivalent numbers with and without mod\_cloudflare.
- If you like, you may also add the directive `DenyAllButCloudFlare`. This will result in all requests from IPs which are not in the `CloudFlareRemoteIPTrustedProxy` range being denied with a status of 403.

  [1]: https://www.cloudflare.com/ips

# mod_cloudflare for Apache #
Copyright CloudFlare Inc. 2013

## mod_cloudflare.c ##

Based on mod_remoteip.c, this Apache extension will replace the remote_ip variable in user's logs with the correct remote IP sent from CloudFlare. The module only performs the IP substitution for requests originating from CloudFlare IPs by default.

To install, follow the instructions on:
    https://www.cloudflare.com/resources-downloads#mod_cloudflare
    
No further configuration is needed. However, if you wish to override the default values, the following directives are exposed:

### CloudFlareRemoteIPHeader ###

This specifies the header which contains the original IP. Default:

    CloudFlareRemoteIPHeader CF-Connecting-IP

### CloudFlareRemoteIPTrustedProxy ###

This is the IP range from which we will allow the `CloudFlareRemoteIPHeader` to be used from. See [here][1] for a complete list.

Note that on some systems, you may have to add a `LoadModule` directive manually. This should look like:

    LoadModule cloudflare_module /usr/lib/apache2/modules/mod_cloudflare.so

Replace `/usr/lib/apache2/modules/mod_cloudflare.so` with the path to `mod_cloudflare.so` on your system.


NOTES:

- If mod\_cloudflare and mod\_remoteip are enabled on the same web server, the server will crash if they both try to set the remote IP to a different value.
- Enabling mod\_cloudflare will not effect the performance of Apache in any noticeable manner. AB testing both over LAN and WAN show no equivalent numbers with and without mod\_cloudflare.
- If you like, you may also add the directive `DenyAllButCloudFlare`. This will result in all requests from IPs which are not in the `CloudFlareRemoteIPTrustedProxy` range being denied with a status of 403.

  [1]: https://www.cloudflare.com/ips

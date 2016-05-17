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

### DenyAllButCloudFlare ###

Denies any request that does not come via cloudflare's proxies (as defined by `CloudFlareRemoteIPTrustedProxy`) with a 403 error.

## Load-balancer handling ##

If there is a load-balancer between your server and cloudflare, you may find the remote IP address is misreported. You can
enable an additional step to process the request as sent from your load balancer, before then handling the cloudflare request.

This will ensure that the IP addresses of your load balancer and the cloudflare proxy are checked to ensure they are trustworthy,
before reading the appropriate headers.

This is also useful in environments where you expect to receive requests both via cloudflare and directly through your load
balancer, to ensure the remote IP is set correctly in both cases. The following directives are available:

### CloudFlareBehindLoadBalancer ###

This enables load-balancer processing. The default is to trust servers that are in a private IP address space, and to use
the 'X-Forwarded-For' header. This is how Amazon's ELB service works, so if you are behind ELB you will likely want to
add this directive.

### CloudFlareLoadBalancerRemoteIPHeader ###

This specifies the header which contains the original IP as proxied by your load balancer. Default:

    CloudFlareLoadBalancerRemoteIPHeader X-Forwarded-For
    
### CloudFlareTrustedLoadBalancer ###

This is the IP range from which we will allow the `CloudFlareLoadBalancerRemoteIPHeader` to be used from. The default
is to trust the entire private IP address space.

### DenyAllButLoadBalancer ###

Denies any request that does not come via your load balancer (as defined by `CloudFlareTrustedLoadBalancer`) with a 403 error.

Note that if this setting is combined with `DenyAllButCloudFlare`, all requests will be denied unless they pass through /both/
cloudflare's servers and your load balancer.

## NOTES ##

Note that on some systems, you may have to add a `LoadModule` directive manually. This should look like:

    LoadModule cloudflare_module /usr/lib/apache2/modules/mod_cloudflare.so

Replace `/usr/lib/apache2/modules/mod_cloudflare.so` with the path to `mod_cloudflare.so` on your system.

- If mod\_cloudflare and mod\_remoteip are enabled on the same web server, the server will crash if they both try to set the remote IP to a different value.
- Enabling mod\_cloudflare will not effect the performance of Apache in any noticeable manner. AB testing both over LAN and WAN show no equivalent numbers with and without mod\_cloudflare.

  [1]: https://www.cloudflare.com/ips

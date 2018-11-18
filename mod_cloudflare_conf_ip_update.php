<?php

// A simple PHP script automatically updating Cloudflare IPs
// in mod_cloudflare's config file at /etc/apache2/mods-available/cloudflare.conf
// Works in Debian and will work in all OSs provided they have PHP and you optionally adjust config file location
// You can uncomment DenyAllButCloudFlare option in config content if you desire too
// Can be added to cron like so (remember about having correct permissions, so the executing user can write the config file):
// 0 0 * * * php /<path>/mod_cloudflare_conf_ip_update.php
//
// Created by p0358

$list = '';
$arr = [];

$ipv4 = file_get_contents('https://www.cloudflare.com/ips-v4');
$ipv6 = file_get_contents('https://www.cloudflare.com/ips-v6');
if (empty($ipv4) || empty($ipv6)) {
    fwrite(STDERR, "Error: script could not download the latest IP ranges from Cloudflare\n");
    exit(1);
}

$ipv4_arr = explode("\n", trim($ipv4));
foreach ($ipv4_arr as &$line) {
    // Source: https://www.regextester.com/98096
    if (preg_match('/^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2])))$/', trim($line), $matches)) {
        $arr[] = $matches[1];
    }
}

$ipv6_arr = explode("\n", trim($ipv6));
foreach ($ipv6_arr as &$line) {
    // Source: https://www.regextester.com/93988
    if (preg_match('/^s*(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?)$/', trim($line), $matches)) {
        $arr[] = $matches[1];
    }
}

if (empty($arr)) {
    fwrite(STDERR, "Error: script got 0 results while trying to get the latest IP ranges from Cloudflare, terminating\n");
    exit(2);
}

//$arr[] = ''; -- you can append your public server's IP(s) here too
$arr[] = '127.0.0.1';
$arr[] = '::1';

$list = implode(' ', $arr);

$datestring = date('Y-m-d H:i:s');

$content = <<<CONTENT
<IfModule mod_cloudflare.c>
    CloudFlareRemoteIPHeader CF-Connecting-IP
    CloudFlareRemoteIPTrustedProxy $list
    #DenyAllButCloudFlare
</IfModule>
# Updated using mod_cloudflare_conf_ip_update.php by p0358 at $datestring
CONTENT;

file_put_contents('/etc/apache2/mods-available/cloudflare.conf', $content);

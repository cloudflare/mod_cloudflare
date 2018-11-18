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

$ipv4_arr = explode("\n", trim($ipv4));
foreach ($ipv4_arr as $line) {
    $arr[] = trim($line);
}

$ipv6_arr = explode("\n", trim($ipv6));
foreach ($ipv6_arr as $line) {
    $arr[] = trim($line);
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

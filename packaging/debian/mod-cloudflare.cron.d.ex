#
# Regular cron jobs for the mod-cloudflare package
#
0 4	* * *	root	[ -x /usr/bin/mod-cloudflare_maintenance ] && /usr/bin/mod-cloudflare_maintenance

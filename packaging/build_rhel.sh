#!/usr/bin/env bash

HOST=root@$1

git archive --format=tar --prefix='mod_cloudflare/' HEAD -o mod_cloudflare.tar.gz
scp -i mod_cloudflare.keypair mod_cloudflare.tar.gz $HOST: 

ssh -i mod_cloudflare.keypair $HOST 'tar -xf mod_cloudflare.tar.gz; cd mod_cloudflare/packaging && make pkg-rpm-system-prep; useradd rpm; chown -R rpm:users /root; su -p rpm -c "cd mod_cloudflare/packaging && make pkg-rpm"'
scp -i mod_cloudflare.keypair $HOST:/root/mod_cloudflare/rpm/RPMS/* . 

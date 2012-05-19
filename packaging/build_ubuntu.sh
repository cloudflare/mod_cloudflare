#!/usr/bin/env bash

HOST=ubuntu@$1

git archive --format=tar --prefix='mod_cloudflare/' HEAD -o mod_cloudflare.tar.gz
scp -i mod_cloudflare.keypair mod_cloudflare.tar.gz $HOST: 

ssh -i mod_cloudflare.keypair $HOST 'tar -xf mod_cloudflare.tar.gz'
ssh -i mod_cloudflare.keypair $HOST 'cd mod_cloudflare/packaging && sudo make pkg-deb-system-prep && make pkg-deb'
scp -i mod_cloudflare.keypair $HOST:/home/ubuntu/mod_cloudflare/*.deb . 

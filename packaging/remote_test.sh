#!/usr/bin/env bash

# remote_test_debian.sh servername test_script pkg_file
#./remote_test_debian.sh root@ec2-50-18-129-171.us-west-1.compute.amazonaws.com test_debian.sh  libapache2-mod-cloudflare_1.1_i386.deb

HOST=$1

scp -i mod_cloudflare.keypair $2 $HOST: 
scp -i mod_cloudflare.keypair $3 $HOST: 

ssh -i mod_cloudflare.keypair $HOST "sh $2 $3"

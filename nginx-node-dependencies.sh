#!/bin/bash

# Installs NodeJS with n version manager and version 5.12.0 of node.
# Can change global npm installs as needed.

NPM_GLOBAL=pm2

yum -y update
yum install -y nginx
yum install -y git
yum install -y gcc gcc-c++ make openssl-devel
cd /tmp
curl -O https://nodejs.org/dist/v4.6.0/node-v4.6.0.tar.gz
tar -xvf node-v4.6.0.tar.gz && rm node-v4.6.0.tar.gz
cd node-v4.6.0/
./configure
make
make install
ln -s /usr/local/bin/node /usr/bin/node
ln -s /usr/local/lib/node /usr/lib/node
ln -s /usr/local/bin/npm /usr/bin/npm  
npm install -g n $NPM_GLOBAL
n 5.12.0
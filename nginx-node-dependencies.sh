#!/bin/bash

# Installs NodeJS with n version manager and version 5.12.0 of node.
# Can change global npm installs as needed.

NPM_GLOBAL=pm2

yum -y update
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
yum install -y nodejs nginx git
yum install -y gcc-c++ make
npm install -g n $NPM_GLOBAL
n 5.12.0

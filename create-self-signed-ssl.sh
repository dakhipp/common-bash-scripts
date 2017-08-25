#!/bin/bash

# Creates a self signed certificate and a privately owned path to house them at.

SSL_ROOT_PATH=/etc/ssl/private
KEY_NAME=site.com.key
CRT_NAME=site.com.crt

sudo mkdir $SSL_ROOT_PATH
sudo chmod 700 $SSL_ROOT_PATH
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $SSL_ROOT_PATH/$KEY_NAME -out $SSL_ROOT_PATH/$CRT_NAME
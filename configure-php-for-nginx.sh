#!/bin/bash

# Configures php-fpm to be used with nginx.

sudo sed -i '/cgi.fix_pathinfo=1/c\cgi.fix_pathinfo=0' /etc/php.ini
sudo sed -i '/user = apache/c\user = nginx' /etc/php-fpm.d/www.conf
sudo sed -i '/group = apache/c\group = nginx' /etc/php-fpm.d/www.conf
sudo service php-fpm restart
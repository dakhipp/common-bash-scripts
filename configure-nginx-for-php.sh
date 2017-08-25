#!/bin/bash

# Depends on running php-fpm process.
# Configures nginx config file to reverse proxy to node processes.
# Configures nginx to handle static assets with compression and caching.
# Redirects IP, HTTP, and WWW to HTTPS version of site.
# Sets some basic security rules in attempt to emulate some naxsi-nginx rules.
# Location of files should be /var/www/html/$SITE_NAME/

# define some constants
IP=34.213.229.24
SITE_NAME=php.dakhipp.com

# create backup of nginx file
if !  [ -e "/etc/nginx/nginx.conf.bak" ]; then
  sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak || true
fi

# create logs and sites-enabled directoies to house all newly created include files and log files
sudo mkdir -p /etc/nginx/sites-enabled/
sudo mkdir -p /logs/

# allow current user to edit files inside newly created directories
sudo chown $USER -R /etc/nginx/
sudo chown $USER -R /logs/

# echo out new nginx config file
echo "user nginx;
worker_processes 1;

pid /var/run/nginx.pid;
     
events {
  worker_connections 1024;
}
             
http {
  include mime.types;
  default_type application/octet-stream;
  sendfile on;

  server_tokens off;

  include /etc/nginx/sites-enabled/ip-redirect;
  
  include /etc/nginx/sites-enabled/www-redirect;

  include /etc/nginx/sites-enabled/$SITE_NAME; 
}" >| /etc/nginx/nginx.conf

# redirects direct ip address traffic to main website
echo "server {
  listen 80;
  listen [::]:80;

  server_name 54.68.55.96;
         
  return 301 https://$SITE_NAME\$request_uri;
}" >| /etc/nginx/sites-enabled/ip-redirect

# redirects www. traffic to main website to avoid duplicate content
echo "server {
  listen 80;
  listen [::]:80;
  listen 443 ssl;

  server_name www.$SITE_NAME;

  include /etc/nginx/sites-enabled/_security-include;
         
  add_header X-Frame-Options \"SAMEORIGIN\";
  return 301 https://$SITE_NAME\$request_uri;
}" >| /etc/nginx/sites-enabled/www-redirect

# main server configuration, includes security file
echo "server {
  listen 80;
  listen [::]:80;
  listen 443 ssl;

  index index.html index.php;

  server_name $SITE_NAME;

  access_log /logs/$SITE_NAME-access-nginx.log;
  error_log /logs/$SITE_NAME-error-nginx.log;

  include /etc/nginx/sites-enabled/_security-include;

  if (\$scheme = http) {
    return 301 https://\$server_name\$request_uri;
  }

  location / { 
    root /var/www/html/$SITE_NAME/;
    try_files \$uri \$uri/ \$uri.html \$uri.php\$is_args\$query_string;
    proxy_pass_request_headers on;
    gzip on; 
    gzip_disable msie6;
    gzip_vary on; 
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types text/plain text/css application/json application/x-javascript application/javascript text/xml application/xml application/xml+rss text/javascript application/vnd.ms-fontobject application/x-font-ttf font/opentype image/svg+xml image/x-icon;
    expires max;
    add_header Cache-Control public;
    server_tokens off;
    fastcgi_hide_header X-Powered-By;
  }
  
  # handle php files
  location ~ \.php\$ {
    root /var/www/html/$SITE_NAME/;
    fastcgi_param SCRIPT_FILENAME /var/www/html/$SITE_NAME\$fastcgi_script_name;
    try_files \$uri =404;
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_index  index.php;
    include fastcgi_params;    
  }
}" >| /etc/nginx/sites-enabled/$SITE_NAME

# security include file. sets up ssl, turns off servier identification, sets some headers, and blocks common attacks
echo "ssl on;
ssl_certificate /etc/ssl/private/$SITE_NAME.crt;
ssl_certificate_key /etc/ssl/private/$SITE_NAME.key;

server_tokens off;

# add_header Strict-Transport-Security \"max-age=31536000; includeSubdomains\" always;
add_header Strict-Transport-Security \"max-age=31536000;\" always;

## Block SQL injections
set \$block_sql_injections 0;
if (\$query_string ~ \"union.*select.*\(\") { 
  set \$block_sql_injections 1;
}
if (\$query_string ~ \"union.*all.*select.*\") {
  set \$block_sql_injections 1;
}
if (\$query_string ~ \"concat.*\(\") {
  set \$block_sql_injections 1;
}
if (\$block_sql_injections = 1) {
  return 403;
}

## Block file injections
set \$block_file_injections 0;
if (\$query_string ~ \"[a-zA-Z0-9_]=http://\") {
  set \$block_file_injections 1;
}
if (\$query_string ~ \"[a-zA-Z0-9_]=(\.\.//?)+\") {
  set \$block_file_injections 1;
}
if (\$query_string ~ \"[a-zA-Z0-9_]=/([a-z0-9_.]//?)+\") {
  set \$block_file_injections 1;
}
if (\$block_file_injections = 1) {
  return 403;
}

## Block common exploits
set \$block_common_exploits 0;
if (\$query_string ~ \"(<|%3C).*script.*(>|%3E)\") {
  set \$block_common_exploits 1;
}
if (\$query_string ~ \"GLOBALS(=|\[|\%[0-9A-Z]{0,2})\") {
  set \$block_common_exploits 1;
}
if (\$query_string ~ \"_REQUEST(=|\[|\%[0-9A-Z]{0,2})\") {
  set \$block_common_exploits 1;
}
if (\$query_string ~ \"proc/self/environ\") {
  set \$block_common_exploits 1;
}
if (\$query_string ~ \"mosConfig_[a-zA-Z_]{1,21}(=|\%3D)\") {
  set \$block_common_exploits 1;
}
if (\$query_string ~ \"base64_(en|de)code\(.*\)\") {
  set \$block_common_exploits 1;
}
if (\$block_common_exploits = 1) {
  return 403;
}

## Block spam
set \$block_spam 0;
if (\$query_string ~ \"\b(ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)\b\") {
  set \$block_spam 1;
}
if (\$query_string ~ \"\b(erections|hoodia|huronriveracres|impotence|levitra|libido)\b\") {
  set \$block_spam 1;
}
if (\$query_string ~ \"\b(ambien|blue\spill|cialis|cocaine|ejaculation|erectile)\b\") {
  set \$block_spam 1;
}
if (\$query_string ~ \"\b(lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby)\b\") {
  set \$block_spam 1;
}
if (\$block_spam = 1) {
  return 403;
}

## Block user agents
set \$block_user_agents 0;

# Don't disable wget if you need it to run cron jobs!
if (\$http_user_agent ~ \"Wget\") {
  set \$block_user_agents 1;
}

# Disable Akeeba Remote Control 2.5 and earlier
if (\$http_user_agent ~ \"Indy Library\") {
  set \$block_user_agents 1;
}

# Common bandwidth hoggers and hacking tools.
if (\$http_user_agent ~ \"libwww-perl\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"GetRight\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"GetWeb!\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"Go!Zilla\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"Download Demon\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"Go-Ahead-Got-It\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"TurnitinBot\") {
  set \$block_user_agents 1;
}
if (\$http_user_agent ~ \"GrabNet\") {
  set \$block_user_agents 1;
}
if (\$block_user_agents = 1) {
  return 403;
}"  >| /etc/nginx/sites-enabled/_security-include

sudo service nginx restart

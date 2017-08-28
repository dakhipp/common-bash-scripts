#!/bin/bash

# Depends on 4 running nodeJS processes, they should be ran with pm2 or forever.
# Current Node ports: 8000, 8001, 8002, 8003
# Configures nginx config file to reverse proxy to node processes.
# Configures nginx to handle static assets with compression and caching.
# Redirects IP, HTTP, and WWW to HTTPS version of site.
# Sets some basic security rules in attempt to emulate some naxsi-nginx rules.

# define some constants
IP=52.33.56.97
SITE_NAME=node.dakhipp.com
STATIC_PATH=/var/www/html/$SITE_NAME/public

# create backup of nginx file
if !  [ -e "/etc/nginx/nginx.conf.bak" ]; then
  cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak || true
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
    # max_clients = worker_processes * worker_connections / 4
    worker_connections 1024;
}
             
http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
                     
    # backend node processes
    upstream nodes {
        server 127.0.0.1:8000;
        server 127.0.0.1:8001;
        server 127.0.0.1:8002;
        server 127.0.0.1:8003;
        keepalive 64;
    }

    include /etc/nginx/sites-enabled/ip-redirect;

		include /etc/nginx/sites-enabled/www-redirect;

    include /etc/nginx/sites-enabled/$SITE_NAME;
}" >| /etc/nginx/nginx.conf

# redirects direct ip address traffic to main website
echo "server {
    listen 80;
    listen [::]:80;

    server_name $IP;
           
    return 301 https://$SITE_NAME\$request_uri;
}" >| /etc/nginx/sites-enabled/ip-redirect

# redirects www. traffic to main website to avoid duplicate content
echo "server {
  listen 80;
  listen [::]:80;
  listen 443 ssl;

  server_name www.$SITE_NAME.com;

  include /etc/nginx/sites-enabled/_security-include;
         
  add_header X-Frame-Options \"SAMEORIGIN\";
  return 301 https://$SITE_NAME.com\$request_uri;
}" >| /etc/nginx/sites-enabled/www-redirect

# main site server configuration, includes security file
echo "server {
    listen 80;
    listen [::]:80;
    listen 443 ssl;

    server_name $SITE_NAME;

    access_log /logs/$SITE_NAME-access-nginx.log;
    error_log /logs/$SITE_NAME-error-nginx.log;

    include /etc/nginx/sites-enabled/_security-include;

		# redirect http to https
    if (\$scheme = http) {
      return 301 https://\$server_name\$request_uri;
    }

    # handle static assets and enable compression and caching 
    location ~ \.(mp3|mp4|webm|png|jpg|svg|jpeg|ttf|woff|woff2|eot|js|css|min.js|min.css|txt|xml) {
        root $STATIC_PATH;
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
    }   

    # everything else goes to backend node app processes
    location / { 
        proxy_pass http://nodes;
        proxy_redirect off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        proxy_set_header X-NginX-Proxy true;
        proxy_set_header Connection \"\"; 
        proxy_http_version 1.1;
        # enable authorization header for tokens and enable CORS
        # proxy_set_header Access-Control-Allow-Headers: authorization;
        # proxy_set_header Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE;
        # proxy_set_header Access-Control-Allow-Origin: *;
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

service nginx restart

#!/bin/bash

# Create SSH key for integrations with source control.
# Still need to paste key in your source control provider.

HOST=github.com

ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
eval `ssh-agent`
ssh-add ~/.ssh/id_rsa
ssh-add -l
ssh-keyscan $HOST >> ~/.ssh/known_hosts
echo "BEFORE RUNNING THE REMAINING SCRIPTS, paste the following into the keys section of bitbucket or github:"
echo ""
cat ~/.ssh/id_rsa.pub
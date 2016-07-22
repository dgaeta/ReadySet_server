#! /bin/bash
# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START startup]
set -v

# Talk to the metadata server to get the project id
PROJECTID=$(curl -s "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")

# Install logging monitor. The monitor will automatically pickup logs sent to
# syslog.
# [START logging]
sudo curl -s "https://storage.googleapis.com/signals-agents/logging/google-fluentd-install.sh" | bash
service google-fluentd restart &
# [END logging]

# Install dependencies from apt
sudo apt-get update
sudo apt-get install -yq \
    git build-essential supervisor python python-dev python-pip libffi-dev \
    libssl-dev


##### I PUT THIS HERE 
sudo add-apt-repository ppa:nginx/stable -y
sudo apt-get --assume-yes update && sudo apt-get --assume-yes upgrade
sudo apt-get --assume-yes install git
sudo apt-get --assume-yes install autoconf g++ python2.7-dev
sudo apt-get --assume-yes install build-essential python python-dev 
sudo apt-get --assume-yes install nginx
sudo apt-get --assume-yes install python-virtualenv
sudo apt-get --assume-yes install npm
sudo apt-get --assume-yes install nodejs
sudo apt-get --assume-yes install uwsgi-plugin-python
sudo /etc/init.d/nginx start

echo 'AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==' >> ~/.ssh/known_hosts 


sudo mkdir /var/www
sudo mkdir /var/www/Readyset_server
sudo chown -R danielgaeta:danielgaeta /var/www/Readyset_server/
cd /var/www/Readyset_server
git init
git pull https://github.com/dgaeta/ReadySet_server.git
# sudo cp parachutefs.com.chained.crt ~/
# sudo cp parachutefs.com.key ~/



cd /var/www/Readyset_server

virtualenv venv
source "venv/bin/activate"
pip install pycrypto

pip install -r requirements.txt

# Set up the uWSGI application server
pip install uwsgi
sudo rm /etc/nginx/sites-enabled/default
sudo ln -s /var/www/Readyset_server/readyset_server_nginx.conf /etc/nginx/conf.d/
sudo /etc/init.d/nginx restart

sudo mkdir -p /var/log/uwsgi
sudo chown -R danielgaeta:danielgaeta /var/log/uwsgi

# uwsgi --ini /var/www/Readyset_server/readyset_server_uwsgi.ini &

sudo cp uwsgi.conf /etc/init/
sudo mkdir /etc/uwsgi && sudo mkdir /etc/uwsgi/vassals
sudo ln -s /var/www/Readyset_server/readyset_server_uwsgi.ini /etc/uwsgi/vassals
sudo chown -R www-data:www-data /var/www/Readyset_server
sudo chown -R www-data:www-data /var/log/uwsgi/

sudo start uwsgi
deactivate
##### END STUFF I PUT 

######## START OF WEB APP ####
# Install node 
cd ~
wget https://nodejs.org/dist/v4.2.3/node-v4.2.3-linux-x64.tar.gz
mkdir node
tar xvf node-v*.tar.?z --strip-components=1 -C ./node
cd ~
rm -rf node-v*
mkdir node/etc
echo 'prefix=/usr/local' > node/etc/npmrc
sudo mv node /opt/
sudo chown -R root: /opt/node
sudo ln -s /opt/node/bin/node /usr/local/bin/node
sudo ln -s /opt/node/bin/npm /usr/local/bin/npm
# End install node

ls
mkdir ~/readyset_client
ls
cd ~/readyset_client
ls
git init
git pull https://github.com/dgaeta/readyset_client.git
ls

npm install 
sudo npm install -g pm2@latest

pm2 start ~/readyset_client/server.js

####### END WEB APP SET UP


# supervisorctl reread
# supervisorctl update

# Application should now be running under supervisor
# [END startup]
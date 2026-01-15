# Step 1: Microsoft Remote Desktop Setup — Linux

Update system packages and install graphical interface
```
sudo apt update
sudo apt install xfce4 xfce4-goodies -y
```

* You will be prompted to choose a display manager, which is a program that manages graphical login mechanisms and user sessions. You can select any option from the list of available display managers, but `gdm3` is preferred.


To install xrdp, run the following command in the terminal
```
sudo apt install xrdp -y
```

Verify the status of xrdp using systemctl
```
sudo systemctl status xrdp
```

* If the status of xrdp is not running, you may have to start the service manually with this command: `sudo systemctl start xrdp`

* For configuration check `/etc/xrdp/xrdp.ini`. By default xrdp will fork a new process upon new connection and will ask for username and password. This behaviour along with many more can be controlled with this file.

Create a .xsession file under /home/sammy and add the xfce4-session as the session manager to use upon login
```
echo "xfce4-session" | tee .xsession
```

Restart the xrdp server
```
sudo systemctl restart xrdp
```

If firewall enabled, execute following to allow connections on port 3389.
```
sudo ufw allow 3389
```

Please refer to following [link](https://www.digitalocean.com/community/tutorials/how-to-enable-remote-desktop-protocol-using-xrdp-on-ubuntu-22-04) for further information on Microsoft Remote Desktop Setup for linux.


Connect to the server using Microsoft Remote Desktop Application on the client-side.

# Step 2: MongoDB Installation

Prerequisites
```
sudo apt-get install libcurl4 libgssapi-krb5-2 libldap-2.5-0 libwrap0 libsasl2-2 libsasl2-modules libsasl2-modules-gssapi-mit openssl liblzma5
```

Download tarball (.tgz) from following [link](https://www.mongodb.com/try/download/community) after selecting platform and version as required. I have selected following:
* Version: 8.0.10 (Current)
* Platform: Ubuntu 22.04 x64
* Package: tgz

Move the tarball to desired directory and unzip it using following command
```
tar -zxvf mongodb-linux-*-8.0.10.tgz
```

To quickly access the binaries of mongodb, create symbolic link for them
```
sudo ln -s /home/vajraopt/ipanalyzer/mongodb-linux-x86_64-ubuntu2204-8.0.10/bin/* /usr/local/bin/
```
* Note: Please replace `/home/vajraopt/ipanalyzer/mongodb-linux-x86_64-ubuntu2204-8.0.10/bin/*` with the appropriate path of bin folder in extracted files.
* Please use absolute paths for symlink.

Create a directory where the MongoDB instance stores its data. E.g.
```
mkdir -p /home/vajraopt/ipanalyzer/mongo/database
```

Create a directory where the MongoDB instance stores its log. E.g.
```
mkdir -p /home/vajraopt/ipanalyzer/mongo/logs
```

Note: Make sure that user who runs MongoDB has appropriate read and write permissions to the respective database and log directories.
* Common paths for database and log directories are as follows:
    * Database: `/var/lib/mongo`
    * Logs: `/var/log/mongodb`
* Use following command for granting ownership of a file or directory to logged-in user ``sudo chown `whoami` <PATH_TO_FILE_OR_DIRECTORY>``

## Start the MongoDB server
```
mongod --dbpath /home/vajraopt/ipanalyzer/mongo/database/ --logpath /home/vajraopt/ipanalyzer/mongo/logs/mongod.log --fork
```
* To know about the options used, please refer to [link](https://www.mongodb.com/docs/manual/reference/program/mongod/#std-label-mongod-options).

Please refer to following [link](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu-tarball/) for further information.

## Stopping the server

To stop the server, first find the PID of the process using the following command
```
ps aux | grep mongod
```
* Second word in first line is the PID. E.g.
    * vajraopt `1306378`  0.6  0.4 3706796 143520 ?      Sl   20:01   0:03 mongod --dbpath mongo/database/ --logpath mongo/logs/mongod.log --fork

Once you have the PID, simply execute following command to sto p the server.
```
kill <PID>
```
* E.g. `kill 1306378`.

# Step 3: MongoDB Shell (Mongosh) Installation

Import the MongoDB public GPG key from https://www.mongodb.org/static/pgp/server-8.0.asc
```
wget -qO- https://www.mongodb.org/static/pgp/server-8.0.asc | sudo tee /etc/apt/trusted.gpg.d/server-8.0.asc
```

Create the `/etc/apt/sources.list.d/mongodb-org-8.0.list` file for Ubuntu 22.04
```
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
```

Reload the local package database
```
sudo apt-get update
```

Install mongosh
```
sudo apt-get install -y mongodb-mongosh
```
* Mongosh depends on OpenSSL. Current system already has OpenSSL 3.0.2. You can check OpenSSL version using the command `openssl version`.
* If you don't have OpenSSL installed, use following commands to install mongosh.
    * For installing mongosh with OpenSSL 1.1 libraries: `sudo apt-get install -y mongodb-mongosh-shared-openssl11`
    * For installing mongosh with OpenSSL 3 libraries: `sudo apt-get install -y mongodb-mongosh-shared-openssl3`

Confirm installation of mongosh using following command
```
mongosh --version
```

Please refer to following [link](https://www.mongodb.com/docs/mongodb-shell/install/) for further information.


# Step 4: MongoDB Compass Installation

Install `.deb` package of MongoDB compass from [link](https://www.mongodb.com/try/download/compass).
* I have used following configuration
    * Version: `1.46.3 (Stable)`
    * Platform: `Ubuntu 64-bit (16.04+)`
    * Package: `.deb`

Install the appliation using following command
```
sudo apt install ./mongodb-compass_1.46.3_amd64.deb
```

# Step 5: Nginx Setup

Install Nginx

```
sudo apt update
sudo apt install nginx
```

Check status of nginx
```
sudo systemctl status nginx
```

If nginx is not running then use following to start the process
```
sudo systemctl start nginx
```

List the configurations for user nginx-firewall.
```
sudo ufw app list
```
* It should give following options:
    * CUPS
    * Nginx Full
    * Nginx HTTP
    * Nginx HTTPS
    * OpenSSH

Allow HTTPS and HTTP for Nginx.
```
sudo ufw allow 'Nginx HTTPS'
sudo ufw allow 'Nginx HTTP'
```

Add following lines in `/etc/nginx/nginx.conf` under http block.
```
server {
    listen 80;
    server_name ipanalyzer;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name ipanalyzer;

    ssl_certificate /home/vajraopt/ipanalyzer/ssl_certs/ipanalyzer.crt;
    ssl_certificate_key /home/vajraopt/ipanalyzer/ssl_certs/ipanalyzer.key;

    location / {
        # root "/Users/cebajel/ip-analyzer/dist/frontend/";
        # try_files $uri $uri/ /index.html;
        proxy_pass https://localhost:4200;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

include servers/*;
```

*Note: Update the ssl_certificate and ssl_certificate_key to respective path of ssl certificate and ssl certificate private key*

After making any changes to nginx.conf, test them by following command
```
sudo nginx -t
```

Once confirmed finalise the changes using following command
```
sudo systemctl restart nginx
```

Please refer to following [link](https://www.digitalocean.com/community/tutorials/how-to-install-nginx-on-ubuntu-20-04) for further information.

# Step 6: Nmap Installation

Update packages
```
sudo apt update
```

Install Nmap
```
sudo apt install nmap
```

Verify installation
```
nmap --version
```

For further information, please refer to [link](https://phoenixnap.com/kb/how-to-install-nmap-ubuntu).

# Step 7: Django Installation

Install python with version >= 3.10 from following [link](https://www.python.org/downloads/).
* Tested on python 3.10 and 3.11

Clone the git repo and go to backend folder and execute following commands
```
sudo apt install python-is-python3
bash setup.sh
```

Activate the environment and start the  backend
```
pipenv shell
sudo "$(pipenv --py)" manage.py runserver 127.0.0.1:8001
```

To deactivate environment use following command
```
exit
```
* Note: Sometimes deactivate doesn't work completely throwing following error upon retyring to activate shell – `Shell for UNKNOWN_VIRTUAL_ENVIRONMENT already activated.
New shell not activated to avoid nested environments.`

To stop the backend, press `Ctrl + C`.

# Step 8: NodeJs and Angular Installation

Install node from following [link](https://nodejs.org/en/download).
* Version 20>= is preferred.
```
sudo apt install nodejs npm
```

Verify the installation
```
node -v
npm -v
```

Install Angular
```
sudo npm install -g @angular/cli
```

Clone the git repo and go to frontend folder. Edit sslCert and sslKey fields in angular.json according to ssl certificate and key paths.

Install all required node modules
```
npm i
```

Start angular frontend
```
ng serve
```

To stop the frontend, press `Ctrl + C`.

# Step 9: Screen command Installation

Updating packages and installing screen
```
sudo apt update
sudo apt install screen
```

Commands
1. Start a screen: `screen -S <CUSTOM_NAME>`
2. List available screens: `screen -ls`
3. Reattach a screen with a particular PID: `screen -r <PID>`. (You can get the PID from command 2.)
4. Detach screen: `ctrl + a d` OR `screen -d <PID>`
5. Killing a screen: `screen -X -S <PID> quit`


# Step 10: Database Visualisation

Open MongoDB compass through Microsoft Remote Desktop and add connection.
* Give it any name you like.
* Go to Authentication tab and put in following information
    * Username: `admin_ip_analyzer`
    * Password: `root_ip_analyzer`
    * Authentication Database: `ip_analyzer`
* Then click on `Save & Connect` to create the connection.

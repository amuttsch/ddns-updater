# ddns-updater
Small webserver to update ddns entries using nsupdate.

## Install
Create a new virutalenv and install all the requirements:

    virtualenv env
    source env/bin/activate
    pip install -r requirements.txt

Next, name your keyfile to `ddns-key.conf` and copy it into your install directory.

Start the server with

    python ddns_updater.py -r -s ns1.example.com -z zone.example.com

where `-s` is the nameserver and `-z` is the zone where the domains are updated.

### Systemd

A simple systemd script can be found [here](https://github.com/amuttsch/ddns-updater/blob/master/ddnsupdater.service).

### Nginx

If you want to run this server behind nginx instead of the flask server, add the following code  to your nginx configuration:

    server {
      listen 0.0.0.0:80;
      server_name example.com;
      server_tokens off;

      location / {
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_set_header X-NginX-Proxy true;
        proxy_pass http://127.0.0.1:5000;
        proxy_redirect off;
      }
    }

## User management
To add a new user, run `python ddns_updater.py -a` and insert all information. Note: the password is stored encrypted using bcrypt.

To modify or delete users, run `sqlite3 database.db` and change / delete the corresponding rows in the `user` table. 

## License
This application is licensed under the MIT license.

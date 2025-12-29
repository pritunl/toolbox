## MongoDB Container

Runs a containerized MongoDB server with authentication. Automatically
initializes a database with a password and creates a non-root user ID 277.

```shell
sudo podman stop mongodb
sudo podman rm mongodb
sudo rm -rf /var/lib/mongo

sudo podman build --no-cache --rm -t mongo .

sudo mkdir /var/lib/mongo
sudo chown 277:277 /var/lib/mongo

# localhost bind
sudo tee /etc/containers/systemd/mongodb-podman.container << EOF
[Unit]
Description=MongoDB Podman Service

[Container]
Image=localhost/mongo
ContainerName=mongodb
Environment=DB_NAME=pritunl-cloud
Environment=CACHE_SIZE=2
User=mongodb
Volume=/var/lib/mongo:/data/db:Z
PublishPort=127.0.0.1:27017:27017
PodmanArgs=--cpus=2 --memory=4g

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# public bind
sudo tee /etc/containers/systemd/mongodb-podman.container << EOF
[Unit]
Description=MongoDB Podman Service

[Container]
Image=localhost/mongo
ContainerName=mongodb
Environment=DB_NAME=pritunl-cloud
Environment=CACHE_SIZE=2
User=mongodb
Volume=/var/lib/mongo:/data/db:Z
PublishPort=27017:27017
PodmanArgs=--cpus=2 --memory=4g

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# start mongodb container
sudo systemctl daemon-reload
sudo systemctl start mongodb-podman.service

# mongodb shell in container
sudo podman exec -it mongodb bash
mongosh -u admin --authenticationDatabase admin
​
# update
sudo podman build --no-cache --rm -t mongo .
sudo systemctl restart mongodb-podman.service

# credentials
sudo cat /var/lib/mongo/credentials.txt

# external mongodb shell
sudo tee /etc/yum.repos.d/mongodb-org.repo << EOF
[mongodb-org]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/8.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-8.0.asc
EOF
sudo dnf -y install mongodb-mongosh
mongosh --host 127.0.0.1 --port 27017 -u admin --authenticationDatabase admin admin
```

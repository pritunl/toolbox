## MongoDB Container

Runs a containerized MongoDB server with authentication. Automatically
initializes a database with a password and creates a non-root user ID 277.

```shell
sudo podman build --rm -t mongo .

sudo mkdir /var/lib/mongo
sudo chown 277:277 /var/lib/mongo

# localhost bind
sudo podman run -d --name mongodb -e DB_NAME=pritunl-cloud -e CACHE_SIZE=2 --cpus 2 --memory 4g --user mongodb -v /var/lib/mongo:/data/db:Z -p 127.0.0.1:27017:27017 localhost/mongo

# public bind
sudo podman run -d --name mongodb -e DB_NAME=pritunl-cloud -e CACHE_SIZE=2 --cpus 2 --memory 4g --user mongodb -v /var/lib/mongo:/data/db:Z -p 27017:27017 localhost/mongo

sudo cat /var/lib/mongo/credentials.txt
```

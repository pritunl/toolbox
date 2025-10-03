## Live Sync

Live sync changes in a directory using rsync and inotifywait.

```shell
sudo dnf install rsync inotify-tools
```

```python
import lsync
lsync.sync(
    source="/home/cloud/git/pritunl-cloud/",
    destinations=[
        "cloud@dev0.pritunl.com:/home/cloud/git/pritunl-cloud/",
        "cloud@dev1.pritunl.com:/home/cloud/git/pritunl-cloud/",
        "cloud@dev2.pritunl.com:/home/cloud/git/pritunl-cloud/",
        "cloud@dev3.pritunl.com:/home/cloud/git/pritunl-cloud/",
    ],
    excludes=[
        ".*",
        "*.key",
        "*.pyc",
        "node_modules",
        "jspm_packages",
        "app/*.js",
        "app/*.js.map",
        "app/**/*.js",
        "app/**/*.js.map"
    ],
    daemon=True,
).join()
```

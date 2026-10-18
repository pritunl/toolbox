## Live Sync

Continuously mirror a local directory to one or more remote directories over SSH using `rsync` and `inotifywait`.

Install the local dependencies:

```shell
sudo dnf install rsync inotify-tools
```

Requires Python 3.8+, rsync 3.1.3+ on both ends, and a recent `inotifywait` with `--no-newline` and `%0` support. Configure SSH access without interactive password prompts, and make `lsync.py` available on your Python import path.

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
        "*.pyc",
        "node_modules",
        "jspm_packages",
        "app/*.js",
        "app/*.js.map",
        "app/**/*.js",
        "app/**/*.js.map",
    ],
    batch_delay=0.3,
    max_batch_delay=2.0,
    resync_interval=None,
    daemon=True,
).join()
```

The source must exist, and source and destination paths must end with `/`. Destinations use SSH syntax: `user@host:/path/`.

### Sync behavior

- **Batched changes:** Rapid edits are grouped together. Changes received during a transfer remain queued for another pass.
- **Independent destinations:** Each destination transfers serially and retries independently, so an unavailable remote does not block the others.
- **Checksums for edits:** Incremental transfers verify the contents of changed files, including rapid saves with unchanged size and timestamps.
- **Quick full scans:** Startup, directory changes, and watcher recovery trigger full scans using file size and nanosecond modification times. Known changed paths still receive checksum verification. Planned watcher rebuilds avoid an extra scan between watch sessions.
- **No periodic scans by default:** `resync_interval=None` disables scheduled full scans. Set a positive interval, such as `900` for 15 minutes, to enable periodic quick scans. A very large pending batch can still trigger a full checksum pass to preserve known changes while bounding memory use.
- **Exclusions:** Patterns use rsync exclusion syntax. Simple basename patterns and literal directory paths also reduce inotify watches and event overhead, including exclusions such as `.*` and `node_modules`. Complex patterns remain enforced by rsync.
- **Retries:** Failed batches remain pending. Vanished source files (rsync exit `24`) use a short retry at the base delay. Other failures, including exit `23`, use exponential backoff up to `max_retry_delay`.

Sync is one-way and uses `--delete`: non-excluded destination files absent from the source are removed. Excluded destination files are protected from deletion. Use one sync job per destination tree.

### Options

The following options are keyword-only. All timing values are in seconds.

| Option | Default | Description |
| --- | --- | --- |
| `batch_delay` | `0.3` | Wait for this quiet period before transferring queued changes. |
| `max_batch_delay` | `2.0` | Limit batching delay during continuous edits. An active transfer or retry backoff can still delay the next batch. |
| `resync_interval` | `None` | Disable periodic scans, or set a positive interval for periodic quick full scans. Replaces the former `reconcile_interval` name. |
| `retry_delay` | `1.0` | Initial failure retry delay and fixed delay for vanished source files. Also the initial watcher restart delay. |
| `max_retry_delay` | `60.0` | Maximum exponential retry delay for transfers and watcher setup failures. |
| `rsync_timeout` | `300.0` | Maximum duration of each rsync process, including startup scans. |
| `io_timeout` | `30` | Rsync I/O timeout; must be a positive integer. |
| `watch_setup_timeout` | `60.0` | Maximum wait for inotify watches to become established before retrying. |
| `ssh_command` | `None` | Custom SSH command. Otherwise use `RSYNC_RSH`, or the built-in noninteractive SSH command with connection timeout and keepalives. |

Timing values must be finite and positive, except that `resync_interval` also accepts `None`. Maximum delays must be at least their corresponding base delays.

### Running and stopping jobs

With `daemon=True`, `sync()` returns a `SyncThread` immediately. Start multiple jobs this way, then keep the process running with `.join()` on the final job. Daemon threads do not keep Python alive by themselves.

Keep the returned job to stop it programmatically:

```python
job = lsync.sync(
    source="/home/cloud/git/pritunl-cloud/",
    destinations=["cloud@dev0.pritunl.com:/home/cloud/git/pritunl-cloud/"],
    daemon=True,
)

# Later, during application shutdown:
job.stop()
job.join()
```

`stop()` cancels active transfers and pending work; it does not flush the queue. With the default `daemon=False`, `sync()` blocks until interrupted with Ctrl-C.

Pending work is held in memory. Restarting performs a quick full scan, but quick scans cannot detect different contents with identical size and exact modification time. With periodic scans disabled, silently missed events may require a restart or manual resync. Sync is not an atomic snapshot of the directory.

"""Reliable, one-way Linux development sync over SSH.

Existing sync(source, destinations, excludes=None, daemon=False) calls work
unchanged. Requires Python 3.8+, rsync >= 3.1.3 on both ends, OpenSSH, and inotifywait
with --no-newline, %0 and q_overflow support (modern inotify-tools).

Normal file edits use checksum-based, path-filtered rsync. Full scans use
size and nanosecond mtime checks, preserving known dirty paths for a separate
checksum pass. Periodic resync is OFF by default. Startup, directory
changes, and watcher recovery still trigger scans. Queue overflow, detected
source-root replacement, an incomplete source index, and oversized pending
batches use a full checksum recovery pass; these are event-driven, not periodic.
An inode index keeps included hardlink aliases consistent without preserving
hardlink topology at the destination. File creation, deletion and renaming
coalesce a local metadata check using inode identity and ctime; only affected
files need checksum transfers. Ordinary known-file edits do not walk the tree.
Writes made solely through excluded or outside-source hardlink aliases cannot
be observed reliably; make edits through paths included in the watched tree.
Simple basename globs and literal path exclusions also prune inotify watches:
existing excluded directories use @path entries, with --exclude filtering
new directories/events. Complex patterns remain rsync-only. Rsync exclusion
rules protect excluded destination files from deletion. The destination is otherwise a mirror:
non-excluded destination-only files can be deleted.

Each destination has one worker, with independent retries. Vanished source
files (rsync exit 24) keep the batch pending for a short retry; other failures
(including exit 23) use exponential backoff. Events arriving
during a transfer belong to the NEXT batch. Pending work is in memory; an
initial full scan repairs differences after restarting the program.

Queued changes converge once writes stop and the destination is reachable.
Without periodic scans, silently missed events may need a restart/rescan.
Quick scans cannot detect different contents with identical size and exact
mtime. This is not a filesystem snapshot or an atomic multi-file deploy.
Use only one sync job per destination tree; do not run the old and new
scripts simultaneously against the same destination.

Optional keyword-only tuning (seconds): batch_delay=0.3, max_batch_delay=2.0,
resync_interval=None, retry_delay=1.0, max_retry_delay=60.0,
rsync_timeout=300.0, io_timeout=30, watch_setup_timeout=60.0.
ssh_command overrides RSYNC_RSH/the default noninteractive SSH command.
Set resync_interval to positive seconds to opt into periodic quick scans.

daemon=True returns a threading.Thread subclass supporting stop() and join().
As before, daemon threads do not keep Python alive: keep the final .join().
When sync() is called on the main thread, default SIGTERM/SIGHUP handlers are
replaced with exit handlers that allow cleanup; custom handlers are preserved.
"""

import atexit
import contextlib
import fnmatch
import math
import os
import pathlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import weakref


print_lock = threading.Lock()
_active_lock = threading.Lock()
_active = weakref.WeakSet()
_signal_guard_depth = 0  # Accessed only by the main thread/signal handler.
_pending_signal = None
_signal_exiting = False
_MAX_PENDING = 4096
_CHECKSUM_ALL = object()  # Event-driven recovery or pending-path overflow.
_SOURCE_VANISHED = object()  # Retry a partial transfer without exponential backoff.
_WATCH_REBUILD = object()  # Planned rebuild of a still-running watcher.
_WATCH_LOST = object()  # Watch state is unreliable; also repair before retrying.
_DEFAULT_SSH = (
    "ssh -oBatchMode=yes -oConnectTimeout=10 "
    "-oServerAliveInterval=15 -oServerAliveCountMax=3"
)


def _log(message):
    with print_lock:
        print(message, flush=True)


def _ere_literal(value):
    # POSIX ERE, not Python regex syntax (no noncapturing groups or \Z).
    return "".join("\\" + char if char in ".^$[]\\(){}*+?|" else char
                   for char in value)


class _WatchExcludes:
    """Conservative rsync subset, used only to reduce watch/event overhead."""

    def __init__(self, patterns):
        self.rules = []
        # --exclude also accepts legacy include/reset rules. Those change
        # first-match precedence, so leave the entire list to rsync.
        if any(pattern == "!" or pattern.startswith(("+ ", "- ")) for pattern in patterns):
            return
        for pattern in patterns:
            anchored = pattern.startswith("/")
            directory_only = pattern.endswith("/")
            core = pattern[1:] if anchored else pattern
            if directory_only:
                core = core[:-1]
            if not core or any(part in ("", ".", "..") for part in core.split("/")):
                continue
            if any(token in core for token in ("**", "[", "\\")):
                continue
            literal_path = anchored or "/" in core
            if literal_path and any(char in core for char in "*?"):
                continue
            self.rules.append((os.fsencode(core), anchored, directory_only, literal_path))

    def matches(self, relative, is_directory=False):
        # Examine each component prefix so an excluded directory also excludes
        # descendants. Match bytes, like rsync and inotifywait under LC_ALL=C.
        parts = os.fsencode(relative).rstrip(b"/").split(b"/")
        if not parts or not parts[0]:
            return False
        prefix = b""
        for index, part in enumerate(parts):
            prefix = prefix + b"/" + part if prefix else part
            for pattern, anchored, directory_only, literal_path in self.rules:
                if directory_only and index == len(parts) - 1 and not is_directory:
                    continue
                if anchored:
                    matched = prefix == pattern
                elif literal_path:
                    matched = prefix == pattern or prefix.endswith(b"/" + pattern)
                else:
                    matched = fnmatch.fnmatchcase(part, pattern)
                if matched:
                    return True
        return False

    def regex(self, source):
        alternatives = []
        for pattern, anchored, directory_only, literal_path in self.rules:
            core = os.fsdecode(pattern)
            if literal_path:
                body = _ere_literal(core)
            elif core == "*":
                body = "[^/]+"  # Never match the watched root itself.
            else:
                body = "".join("[^/]*" if char == "*" else "[^/]" if char == "?"
                               else _ere_literal(char) for char in core)
            prefix = "" if anchored else "([^/]+/)*"
            # Directory-only patterns must not hide a same-named regular file.
            suffix = "/" if directory_only else "(/|$)"
            alternatives.append(prefix + body + suffix)
        if not alternatives:
            return None
        # Anchor BELOW source: .* must not match a hidden ancestor of source,
        # nor node_modules the source directory's own basename.
        return "^" + _ere_literal(source) + "(" + "|".join(alternatives) + ")"


def _termination_handler(signum, frame):
    # Python handlers interrupt the main thread, possibly inside our own locks.
    # Do no cleanup or locking here: unwind first, then use finally/atexit.
    global _pending_signal, _signal_exiting
    if _signal_exiting:
        return
    if _pending_signal is None:
        _pending_signal = signum
    if _signal_guard_depth == 0:
        signum = _pending_signal
        _pending_signal = None
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        _signal_exiting = True
        raise SystemExit(128 + signum)


def _install_signal_handlers():
    if threading.current_thread() is not threading.main_thread():
        return
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        default = signal.default_int_handler if signum == signal.SIGINT else signal.SIG_DFL
        if signal.getsignal(signum) == default:
            signal.signal(signum, _termination_handler)


@contextlib.contextmanager
def _defer_termination():
    """Finish ownership registration before allowing our signal to unwind."""
    global _signal_guard_depth
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    _signal_guard_depth += 1
    try:
        yield
    finally:
        _signal_guard_depth -= 1
        if _signal_guard_depth == 0 and _pending_signal is not None:
            _termination_handler(_pending_signal, None)


class _ManagedProcess:
    """Keep the session-leader PID reserved until its entire group is killed.

    Ordinary Popen.poll()/wait() reap the leader immediately. A surviving SSH
    helper could then outlive it, and a later killpg could target a reused PID.
    WNOWAIT observes completion while retaining the leader as our waitable
    child. Only cleanup reaps it, after the final process-group signal.
    """

    def __init__(self, cmd, **kwargs):
        self._lock = threading.RLock()
        self._reaped = False
        self._returncode = None
        self._process = subprocess.Popen(cmd, **kwargs)

    def __getattr__(self, name):
        return getattr(self._process, name)

    @property
    def returncode(self):
        return self._returncode

    def poll(self):
        with self._lock:
            if self._reaped:
                return self._returncode
            try:
                status = os.waitid(os.P_PID, self.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                # An application SIGCHLD handler may have reaped our child.
                # Ownership is no longer provable: never signal a stale PGID.
                self._reaped = True
                self._returncode = self._process.poll()
                return self._returncode
            if status is not None:
                self._returncode = (status.si_status if status.si_code == os.CLD_EXITED
                                    else -status.si_status)
            return self._returncode

    def wait(self, timeout=None):
        # Preserve the reserved PID even when callers wait for completion.
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(0.01)

    def signal_group(self, sig):
        with self._lock:
            if self._reaped:
                return
            # Check for an external reaper before using the reserved PGID.
            self.poll()
            if not self._reaped:
                try:
                    os.killpg(self.pid, sig)
                except ProcessLookupError:
                    pass

    def cleanup(self, force=False):
        with _defer_termination(), self._lock:
            if self._reaped:
                return
            if not force:
                self.signal_group(signal.SIGTERM)
                try:
                    self.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            # Always signal the group, even if its leader has already exited.
            # Its unreaped PID still pins the group identity at this point.
            self.signal_group(signal.SIGKILL)
            self._returncode = self._process.wait()
            self._reaped = True
            for stream in (self.stdout, self.stderr):
                if stream is not None:
                    stream.close()


def _signal_process(process, sig):
    if isinstance(process, _ManagedProcess):
        process.signal_group(sig)
    elif process.poll() is None:
        # Compatibility for callers/tests supplying an ordinary Popen. A
        # reaped unmanaged PID cannot safely identify an owned process group.
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass


def _reap(process, force=False):
    if isinstance(process, _ManagedProcess):
        process.cleanup(force)
        return
    _signal_process(process, signal.SIGKILL if force else signal.SIGTERM)
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        _signal_process(process, signal.SIGKILL)
        process.wait()
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


class _SourceIndex:
    """Watch-thread-owned inode/ctime index; ordinary edits only stat one path.

    Index single-link files too: they can gain another name between events.
    Rsync remains responsible for complex exclusions not pruned by the watcher.
    """

    def __init__(self, source, excludes, stop_event):
        self.source = source
        self.excludes = excludes
        self.stop_event = stop_event
        self.paths = {}
        self.stamps = {}
        self.aliases = {}
        self.initialized = False
        self.complete = False
        self.verify_needed = False

    @staticmethod
    def _snapshot(path):
        info = os.lstat(path)
        if stat.S_ISREG(info.st_mode):
            return (info.st_dev, info.st_ino), info.st_ctime_ns
        return None, None

    def _scan(self, relative):
        found = {}
        complete = True

        def failed(error):
            nonlocal complete
            complete = False

        base = os.path.join(self.source, relative)
        try:
            mode = os.lstat(base).st_mode
        except FileNotFoundError:
            return found, True
        except OSError:
            return found, False
        if not stat.S_ISDIR(mode):
            return found, True
        for root, directories, files in os.walk(base, topdown=True, followlinks=False,
                                               onerror=failed):
            if self.stop_event.is_set():
                return found, False
            directories[:] = [name for name in directories if not self.excludes.matches(
                os.path.join(root, name)[len(self.source):], True)]
            for name in files:
                path = os.path.join(root, name)
                name = path[len(self.source):]
                if self.excludes.matches(name):
                    continue
                try:
                    identity, stamp = self._snapshot(path)
                except FileNotFoundError:
                    continue
                except OSError:
                    complete = False
                    continue
                if identity is not None:
                    found[name] = identity, stamp
        return found, complete

    def _remove(self, path):
        identity = self.paths.pop(path, None)
        self.stamps.pop(path, None)
        if identity is not None:
            aliases = self.aliases[identity]
            aliases.remove(path)
            if not aliases:
                del self.aliases[identity]

    def _add(self, path, identity, stamp):
        self.paths[path] = identity
        self.stamps[path] = stamp
        self.aliases.setdefault(identity, set()).add(path)

    def refresh(self, relative=""):
        """Refresh startup/rebuilt watches or one structurally changed subtree.

        Return affected aliases. For a subtree, omit its own paths because its
        directory checksum pass already covers them, including deletions.
        """
        found, complete = self._scan(relative)
        prefix = relative.rstrip("/") + "/" if relative else ""
        old = {path: (identity, self.stamps[path]) for path, identity in self.paths.items()
               if not relative or path == relative or path.startswith(prefix)}
        if relative:
            identities = {value[0] for value in old.values()}
            identities.update(value[0] for value in found.values())
        else:
            changed = {path for path in old.keys() | found.keys()
                       if old.get(path) != found.get(path)}
            identities = {old[path][0] for path in changed if path in old}
            identities.update(found[path][0] for path in changed if path in found)
        affected = set()
        for identity in identities:
            affected.update(self.aliases.get(identity, ()))
        for path in old:
            self._remove(path)
        for path, (identity, stamp) in found.items():
            self._add(path, identity, stamp)
        for identity in identities:
            affected.update(self.aliases.get(identity, ()))
        if relative:
            self.complete = self.complete and complete
            return {path for path in affected
                    if path != relative and not path.startswith(prefix)}
        was_initialized = self.initialized
        self.initialized = True
        self.complete = complete
        self.verify_needed = False
        return affected if was_initialized else set()

    def changed(self, relative, data_event, structural):
        previous = self.paths.get(relative)
        affected = {relative}
        affected.update(self.aliases.get(previous, ()))
        try:
            current, stamp = self._snapshot(os.path.join(self.source, relative))
            missing = False
        except OSError:
            current = None
            missing = True
        self._remove(relative)
        if current is not None:
            self._add(relative, current, stamp)
            affected.update(self.aliases[current])
        # A temporary link may already be gone/replaced when its event arrives.
        # Link/write/unlink changes the surviving inode's ctime. Coalesce a
        # local metadata check, then checksum only paths that actually changed.
        # Keep per-PATH stamps: updating one alias must not hide another's edit.
        if structural or (data_event and (missing or previous is None)):
            self.verify_needed = True
        if data_event and not self.complete:
            return _CHECKSUM_ALL
        return affected


def _escape_pattern(path, wildcard=False):
    # Rsync only interprets backslash escapes if a wildcard marker is present.
    if wildcard or any(char in path for char in "*?["):
        return "".join("\\" + char if char in "\\*?[" else char for char in path)
    return path


def _write_filter(stream, paths):
    rules = set()
    for path in paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            rules.add("+ /" + _escape_pattern(parent) + "/")
        rules.add("+ /" + _escape_pattern(path))
        # Also handle a file/directory type change at this path. Including
        # descendants allows --delete to remove an old populated directory.
        rules.add("+ /" + _escape_pattern(path, wildcard=True) + "/***")
    for rule in sorted(rules):
        stream.write(os.fsencode(rule) + b"\0")
    stream.write(b"- *\0")
    stream.flush()


def _transfer(owner, destination, paths):
    """Copy a batch; return True, False, or _SOURCE_VANISHED for a soft retry.

    paths=None selects a full quick scan; a set selects targeted checksums;
    _CHECKSUM_ALL selects a full checksum pass.
    """
    if owner._stop_event.is_set():
        return False
    if not os.path.isdir(owner.source):
        _log("[lsync] Source unavailable; keeping work pending: " + owner.source)
        return False

    cmd = [
        "rsync", "-az", "--delete", "--itemize-changes",
        "--protect-args", "--timeout=" + str(owner.io_timeout),
        "--rsh=" + owner.ssh_command,
    ]
    cmd.append("--modify-window=-1" if paths is None else "--checksum")
    # User excludes MUST precede generated includes (first matching rule wins).
    for pattern in owner.excludes:
        cmd.append("--exclude=" + pattern)

    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="lsync-") as temp:
            if paths is not None and paths is not _CHECKSUM_ALL:
                filter_path = os.path.join(temp, "filter")
                with open(filter_path, "wb") as stream:
                    _write_filter(stream, paths)
                cmd.extend(["--from0", "--filter=. " + filter_path])
            cmd.extend(["--", owner.source, destination])

            # File-backed output keeps memory bounded during a large initial
            # copy and avoids pipe deadlocks while waiting for subprocesses.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = owner._spawn(cmd, stdout=stdout, stderr=stderr)
                deadline = time.monotonic() + owner.rsync_timeout
                while process.poll() is None:
                    if owner._stop_event.wait(0.1):
                        _reap(process)
                        return False
                    if time.monotonic() >= deadline:
                        _log("[lsync] Transfer timed out: " + destination)
                        _reap(process)
                        return False

                stdout.seek(0)
                stderr.seek(0)
                output = stdout.read(65536).decode("utf-8", "replace").strip()
                error = stderr.read(16384).decode("utf-8", "replace").strip()
                if process.returncode == 24:
                    _log("[lsync] Source files vanished during transfer to {}; "
                         "keeping batch pending: {}".format(destination, error or output))
                    return _SOURCE_VANISHED
                if process.returncode != 0:
                    _log("[lsync] Transfer failed ({}) {}: {}".format(
                        process.returncode, destination, error or output))
                    return False
                if error:
                    _log("[lsync] rsync warning for {}: {}".format(destination, error))
                if output:
                    lines = output.splitlines()
                    shown = "\n".join("  " + line for line in lines[:20])
                    if len(lines) > 20:
                        shown += "\n  ... additional changes omitted"
                    _log("[lsync] {} -> {}\n{}".format(owner.source, destination, shown))
                return True
    except (OSError, subprocess.SubprocessError) as exc:
        _log("[lsync] Transfer error for {}: {}".format(destination, exc))
        return False
    finally:
        if process is not None:
            _reap(process)
            owner._forget(process)


class _DestinationWorker(threading.Thread):
    def __init__(self, owner, destination):
        super().__init__(name="lsync-copy:" + destination, daemon=True)
        self.owner = owner
        self.destination = destination
        self.condition = threading.Condition()
        self.paths = set()
        self.full = False
        self.checksum_full = False
        self.first = None
        self.last = None
        self.retry_at = 0.0
        self.backoff = owner.retry_delay
        self.next_full = (time.monotonic() + owner.resync_interval
                          if owner.resync_interval is not None else None)

    def _merge(self, paths, now, immediate=False):
        # A quick full scan cannot replace checksum verification of known edits.
        if self.first is None:
            self.first = now
        self.last = now
        if paths is _CHECKSUM_ALL:
            self.full = self.checksum_full = True
            self.paths.clear()
        elif paths is None:
            self.full = True
        elif not self.checksum_full:
            self.paths.update(paths)
            if len(self.paths) > _MAX_PENDING:
                self.full = self.checksum_full = True
                self.paths.clear()
        if immediate:
            self.first = now - self.owner.max_batch_delay

    def mark(self, paths=None, immediate=False):
        with self.condition:
            self._merge(paths, time.monotonic(), immediate)
            self.condition.notify()

    def run(self):
        owner = self.owner
        while not owner._stop_event.is_set():
            with self.condition:
                while not owner._stop_event.is_set():
                    now = time.monotonic()
                    if not owner._sync_enabled.is_set():
                        self.condition.wait(timeout=0.5)
                        continue
                    if self.next_full is not None and now >= self.next_full:
                        self._merge(None, now, immediate=True)
                        self.next_full = now + owner.resync_interval
                    if self.first is None:
                        self.condition.wait(timeout=(max(0.01, self.next_full - now)
                                                     if self.next_full is not None else None))
                        continue
                    deadline = max(self.retry_at, min(
                        self.last + owner.batch_delay,
                        self.first + owner.max_batch_delay,
                    ))
                    if now < deadline:
                        timeout = deadline - now
                        if self.next_full is not None:
                            timeout = min(timeout, max(0.01, self.next_full - now))
                        self.condition.wait(timeout=timeout)
                        continue

                    # Ownership transfer under the same lock used by mark().
                    # The reader can immediately start accumulating a new batch.
                    if self.full:
                        batch = _CHECKSUM_ALL if self.checksum_full else None
                    else:
                        batch = self.paths
                        self.paths = set()
                    self.full = False
                    self.checksum_full = False
                    if not self.paths:
                        self.first = self.last = None
                    break
                else:
                    return
                if owner._stop_event.is_set():
                    return

            try:
                success = _transfer(owner, self.destination, batch)
            except Exception as exc:
                # An unexpected transfer error must not silently kill a worker.
                _log("[lsync] Worker error for {}: {!r}".format(self.destination, exc))
                success = False

            with self.condition:
                now = time.monotonic()
                if success is True:
                    self.retry_at = 0.0
                    self.backoff = owner.retry_delay
                    if (batch is None or batch is _CHECKSUM_ALL) and owner.resync_interval is not None:
                        self.next_full = now + owner.resync_interval
                elif not owner._stop_event.is_set():
                    self._merge(batch, now)
                    if success is _SOURCE_VANISHED:
                        self.backoff = owner.retry_delay
                        delay = owner.retry_delay
                    else:
                        delay = self.backoff
                        self.backoff = min(owner.max_retry_delay, self.backoff * 2)
                    self.retry_at = now + delay
                    _log("[lsync] Retrying {} in {:.1f}s".format(self.destination, delay))


class SyncThread(threading.Thread):
    """A sync job. stop() cancels it; join() waits for its workers to exit."""

    def __init__(self, source, destinations, excludes, daemon, **options):
        super().__init__(name="lsync:" + source, daemon=daemon)
        self.source = source
        self.destinations = tuple(destinations)
        self.excludes = tuple(excludes)
        self._watch_excludes = _WatchExcludes(self.excludes)
        self._watch_pruned = set()
        for key, value in options.items():
            setattr(self, key, value)
        self._stop_event = threading.Event()
        self._source_index = _SourceIndex(source, self._watch_excludes, self._stop_event)
        self._root_identity = None
        self._sync_enabled = threading.Event()
        self.ready = threading.Event()  # Watches established, not copy completion.
        self._watch_generation = 0
        self._process_lock = threading.Lock()
        self._processes = set()
        self._workers = [_DestinationWorker(self, dest) for dest in destinations]

    def _spawn(self, cmd, **kwargs):
        # Coordinate spawn with stop(): no child can escape cancellation.
        # A signal in foreground mode may arrive between Popen and tracking.
        # Defer only our handler until the child is registered and lock freed.
        with _defer_termination(), self._process_lock:
            if self._stop_event.is_set():
                raise OSError("sync job stopped")
            process = _ManagedProcess(
                cmd, stdin=subprocess.DEVNULL, start_new_session=True, **kwargs)
            self._processes.add(process)
            return process

    def _forget(self, process):
        with self._process_lock:
            self._processes.discard(process)

    def stop(self):
        """Request shutdown, cancelling in-flight copies and pending work."""
        with self._process_lock:
            self._stop_event.set()
            for process in self._processes:
                _signal_process(process, signal.SIGTERM)
        for worker in self._workers:
            with worker.condition:
                worker.condition.notify_all()

    def _mark(self, paths=None, immediate=False):
        for worker in self._workers:
            worker.mark(paths, immediate)

    def _enable(self):
        self._sync_enabled.set()
        self._mark(None, immediate=True)

    def _refresh_index(self):
        try:
            info = os.stat(self.source)
            identity = info.st_dev, info.st_ino
        except OSError:
            identity = None
        if identity is not None:
            if self._root_identity is not None and identity != self._root_identity:
                self._mark(_CHECKSUM_ALL)
            self._root_identity = identity
        affected = self._source_index.refresh()
        if affected:
            self._mark(affected)

    def _event(self, event, filepath):
        flags = set(event.split(","))
        # Overflow invalidates the watch state; structural changes can leave
        # inotifywait reporting old directory paths. Rebuild all watches.
        if flags & {"Q_OVERFLOW", "UNMOUNT", "IGNORED"}:
            # We no longer know which file contents changed. This rare,
            # event-driven recovery also catches metadata-preserving writes.
            self._mark(_CHECKSUM_ALL)
            return _WATCH_LOST
        if filepath.startswith(self.source):
            relative = filepath[len(self.source):]
            if self._watch_excludes.matches(relative, "ISDIR" in flags):
                # Directory-only regexes cannot filter a CREATE path lacking
                # a trailing slash without also hiding same-named files.
                # If such an event gets through, rebuild the explicit @ list.
                return (_WATCH_REBUILD if "ISDIR" in flags and
                        flags & {"CREATE", "MOVED_TO"} else False)
        if flags & {"DELETE_SELF", "MOVE_SELF"}:
            if filepath.rstrip("/") == self.source.rstrip("/"):
                self._mark(_CHECKSUM_ALL)
                return _WATCH_LOST
            if filepath.startswith(self.source):
                relative = filepath[len(self.source):].rstrip("/")
                if relative and all(part not in ("", ".", "..") for part in relative.split("/")):
                    self._mark({relative} | self._source_index.refresh(relative))
            self._mark(None)
            return _WATCH_LOST
        if not filepath.startswith(self.source):
            self._mark(None)
            return _WATCH_LOST
        if "ISDIR" in flags:
            structural = bool(flags & {"CREATE", "DELETE", "MOVED_FROM", "MOVED_TO"})
            relative = filepath[len(self.source):].rstrip("/")
            if structural and relative and all(part not in ("", ".", "..")
                                                for part in relative.split("/")):
                # Checksum moved/created trees and their hardlink aliases.
                # ATTRIB alone needs only the quick metadata scan below.
                self._mark({relative} | self._source_index.refresh(relative))
            self._mark(None)
            return _WATCH_REBUILD if structural else False
        relative = filepath[len(self.source):]
        if not relative or any(part in ("", ".", "..") for part in relative.split("/")):
            self._mark(None)
        else:
            data_event = bool(flags & {"CREATE", "MOVED_TO", "MODIFY", "CLOSE_WRITE"})
            structural = bool(flags & {"CREATE", "DELETE", "MOVED_FROM", "MOVED_TO"})
            self._mark(self._source_index.changed(relative, data_event, structural))
        return False

    def _excluded_watch_directories(self):
        excluded = set()
        if not self._watch_excludes.rules:
            return excluded
        for root, directories, _ in os.walk(self.source, topdown=True, followlinks=False):
            if self._stop_event.is_set():
                break
            kept = []
            for name in directories:
                path = os.path.join(root, name)
                relative = path[len(self.source):]
                if self._watch_excludes.matches(relative, True):
                    excluded.add(path)
                else:
                    kept.append(name)
            # Never descend into ignored subtrees, including node_modules/.git.
            directories[:] = kept
        return excluded

    def _watch_command(self, watch_file):
        self._watch_pruned = self._excluded_watch_directories()
        cmd = [
            "inotifywait", "--recursive", "--monitor", "--no-dereference",
            "--event", "modify,close_write,attrib,create,delete,move,delete_self,move_self,unmount,q_overflow",
            "--format", "%e%0%w%f%0", "--no-newline",
        ]
        regex = self._watch_excludes.regex(self.source)
        if regex:
            cmd.extend(["--exclude", regex])
        extra_args = []
        for path in sorted(self._watch_pruned):
            entry = "@" + path
            if "\n" in entry or "\r" in entry:
                # --fromfile is line-delimited; argv preserves unusual names.
                extra_args.append(entry)
            else:
                watch_file.write(os.fsencode(entry) + b"\n")
        watch_file.flush()
        # A file avoids ARG_MAX for repositories with many ignored directories.
        cmd.extend(["--fromfile", watch_file.name, "--", self.source] + extra_args)
        return cmd

    def _watch_session(self):
        self._refresh_index()
        with tempfile.NamedTemporaryFile(mode="wb", prefix="lsync-watches-") as watch_file:
            return self._watch_process(self._watch_command(watch_file))

    def _watch_process(self, cmd):
        env = dict(os.environ, LC_ALL="C")
        process = self._spawn(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              bufsize=0, env=env)
        started = time.monotonic()
        buffers = {"out": b"", "err": b""}
        fields = []
        rebuild_at = None
        verify_at = None
        rebuild_reason = _WATCH_REBUILD
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "out")
                selector.register(process.stderr, selectors.EVENT_READ, "err")
                while not self._stop_event.is_set():
                    now = time.monotonic()
                    if verify_at is not None and now >= verify_at:
                        if self._source_index.verify_needed:
                            self._refresh_index()
                        verify_at = None
                    if rebuild_at is not None and now >= rebuild_at:
                        # A process that died during the debounce window is
                        # unexpected loss, even if a planned rebuild was queued.
                        return (rebuild_reason if self.ready.is_set() and process.poll() is None
                                else _WATCH_LOST)
                    if not self.ready.is_set() and now - started >= self.watch_setup_timeout:
                        _log("[lsync] Watch setup timed out; scanning once and retrying watches: " + self.source)
                        return
                    for key, _ in selector.select(timeout=0.2):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        kind = key.data
                        buffers[kind] += data
                        if kind == "err":
                            while b"\n" in buffers[kind]:
                                line, buffers[kind] = buffers[kind].split(b"\n", 1)
                                if line.strip() == b"Watches established.":
                                    self._refresh_index()
                                    self.ready.set()
                                    self._watch_generation += 1
                                    self._enable()
                                    # Close the scan-to-watch setup gap: an
                                    # excluded directory created during setup
                                    # may have escaped the initial @ list.
                                    if self._excluded_watch_directories() - self._watch_pruned:
                                        rebuild_at = time.monotonic() + self.batch_delay
                                elif not line.startswith(b"Setting up watches"):
                                    _log("[lsync] Watcher {}: {}".format(
                                        self.source, os.fsdecode(line)))
                        else:
                            while b"\0" in buffers[kind]:
                                field, buffers[kind] = buffers[kind].split(b"\0", 1)
                                fields.append(os.fsdecode(field))
                                if len(fields) == 2:
                                    rebuild = self._event(*fields)
                                    fields.clear()
                                    if rebuild and rebuild_at is None:
                                        rebuild_at = time.monotonic() + self.batch_delay
                                    if rebuild is _WATCH_LOST:
                                        rebuild_reason = _WATCH_LOST
                                    if self._source_index.verify_needed and verify_at is None:
                                        # Fixed deadline coalesces bursts without
                                        # starving verification during churn.
                                        verify_at = time.monotonic() + self.batch_delay
                        if len(buffers[kind]) > 1024 * 1024:
                            raise RuntimeError("unrecognized or oversized inotifywait output")
                    if process.poll() is not None and not selector.get_map():
                        _log("[lsync] Watcher exited ({}): {}".format(process.returncode, self.source))
                        return
        finally:
            self.ready.clear()
            _reap(process)
            self._forget(process)

    def run(self):
        with _active_lock:
            _active.add(self)
        started_workers = []
        watch_retry = self.retry_delay
        warned_no_watch = False
        try:
            _log("[lsync] Watching {} -> {}".format(self.source, ", ".join(self.destinations)))
            for worker in self._workers:
                worker.start()
                started_workers.append(worker)
            while not self._stop_event.is_set():
                generation = self._watch_generation
                result = None
                try:
                    result = self._watch_session()
                except Exception as exc:
                    if not self._stop_event.is_set():
                        _log("[lsync] Watcher error for {}: {!r}".format(self.source, exc))
                if self._stop_event.is_set():
                    break
                # Planned rebuilds get their repair scan when replacement
                # watches are live. On unexpected loss, also repair once now
                # in case replacement watches cannot be established.
                if (not self._sync_enabled.is_set() or
                        (self._watch_generation != generation and result is not _WATCH_REBUILD)):
                    self._enable()
                if self._watch_generation != generation:
                    watch_retry = self.retry_delay
                    warned_no_watch = False
                elif self.resync_interval is None and not warned_no_watch:
                    _log("[lsync] Live watching unavailable for {}; periodic scans are disabled. "
                         "Further changes may wait until watching recovers.".format(self.source))
                    warned_no_watch = True
                self._stop_event.wait(watch_retry)
                if self._watch_generation == generation:
                    watch_retry = min(self.max_retry_delay, watch_retry * 2)
        finally:
            self.stop()
            for worker in started_workers:
                worker.join()
            # A deferred signal may unwind _spawn after registering its child
            # but before the caller receives it and enters its own finally.
            with self._process_lock:
                processes = list(self._processes)
            for process in processes:
                _reap(process)
                self._forget(process)
            with _active_lock:
                _active.discard(self)


def sync(source, destinations, excludes=None, daemon=False, *,
         batch_delay=0.3, max_batch_delay=2.0, resync_interval=None,
         retry_delay=1.0, max_retry_delay=60.0, rsync_timeout=300.0,
         io_timeout=30, watch_setup_timeout=60.0, ssh_command=None):
    """Mirror source to remote destinations, continuously until stopped.

    With daemon=True, returns SyncThread immediately. Otherwise blocks until
    Ctrl-C and returns None. Arguments are copied; caller lists are not edited.
    Configuration errors raise in the calling thread, before starting workers.

    batch_delay waits for a quiet period; max_batch_delay bounds batching
    during continuous edits. resync_interval=None disables periodic scans;
    a positive interval enables quick full scans, without checksumming the tree.
    Startup and watcher recovery scans still run when periodic scans are off.
    retry_delay and max_retry_delay control failure backoff. Vanished source
    files (exit 24) retain pending work and retry at the base delay.
    rsync_timeout limits each transfer; io_timeout is rsync's I/O timeout.
    watch_setup_timeout limits watch setup. All intervals are in seconds.
    ssh_command overrides RSYNC_RSH or the default noninteractive SSH command.

    Calling sync() from the main thread installs cleanup-on-exit handlers for
    SIGTERM/SIGHUP only when their handlers are still SIG_DFL. Custom/ignored
    handlers are preserved. Default SIGINT still raises KeyboardInterrupt,
    deferred briefly while registering or reaping a child. Applications with
    their own signal handling, or calling sync() only from other threads, must
    stop()/join() jobs themselves.
    """
    if not isinstance(source, str) or not source.endswith("/"):
        raise ValueError("source must be a directory path ending in /")
    source = str(pathlib.Path(source).expanduser().resolve()).rstrip("/") + "/"
    if not os.path.isdir(source):
        raise ValueError("source directory does not exist: " + source)
    if isinstance(destinations, (str, bytes)):
        raise TypeError("destinations must be a sequence of remote paths")
    destinations = tuple(dict.fromkeys(destinations))
    if not destinations:
        raise ValueError("at least one destination is required")
    remote_pattern = re.compile(r"^(?:[^@\s:]+@)?(?:\[[^\]]+\]|[^:\s]+):([^:].*)$")
    for destination in destinations:
        if not isinstance(destination, str) or "\0" in destination:
            raise ValueError("invalid destination")
        if not destination.endswith("/") or not remote_pattern.match(destination):
            raise ValueError("destination must be host:path/ (SSH): " + destination)
    if isinstance(excludes, (str, bytes)):
        raise TypeError("excludes must be a sequence of rsync patterns")
    excludes = tuple(excludes or ())
    if any(not isinstance(pattern, str) or "\0" in pattern for pattern in excludes):
        raise ValueError("excludes must contain strings without NUL characters")
    timings = dict(
        batch_delay=batch_delay, max_batch_delay=max_batch_delay,
        resync_interval=resync_interval, retry_delay=retry_delay,
        max_retry_delay=max_retry_delay, rsync_timeout=rsync_timeout,
        watch_setup_timeout=watch_setup_timeout,
    )
    for name, value in timings.items():
        if name == "resync_interval" and value is None:
            continue
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(name + " must be a finite positive number")
    if max_batch_delay < batch_delay or max_retry_delay < retry_delay:
        raise ValueError("maximum delays must be >= their base delays")
    if not isinstance(io_timeout, int) or io_timeout < 1:
        raise ValueError("io_timeout must be a positive integer")
    for executable in ("rsync", "inotifywait"):
        if shutil.which(executable) is None:
            raise RuntimeError("required executable not found: " + executable)
    ssh_command = ssh_command or os.environ.get("RSYNC_RSH") or _DEFAULT_SSH
    if not isinstance(ssh_command, str) or "\0" in ssh_command:
        raise ValueError("ssh_command must be a string without NUL characters")

    job = SyncThread(source, destinations, excludes, bool(daemon),
                     io_timeout=io_timeout, ssh_command=ssh_command, **timings)
    _install_signal_handlers()
    # Register before starting: a signal must see a job even before its run()
    # method gets a turn. Do not leave a started thread untracked on exit.
    with _defer_termination():
        with _active_lock:
            _active.add(job)
        if daemon:
            try:
                job.start()
            except BaseException:
                job.stop()
                with _active_lock:
                    _active.discard(job)
                raise
            return job
    try:
        job.run()
    except KeyboardInterrupt:
        job.stop()
    return None


def _shutdown():
    global _signal_exiting
    _signal_exiting = True  # Further installed signals must not interrupt cleanup.
    with _active_lock:
        jobs = list(_active)
    for job in jobs:
        job.stop()
    # Daemon threads may not get another turn. Complete idempotent cleanup here
    # too, without holding owner locks while another thread reaps a child.
    for job in jobs:
        with job._process_lock:
            processes = list(job._processes)
        for process in processes:
            _reap(process, force=True)
            job._forget(process)


atexit.register(_shutdown)

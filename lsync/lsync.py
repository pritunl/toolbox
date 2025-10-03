import subprocess
import sys
import pathlib
import typing
import tempfile
import time
import threading
import re

print_lock = threading.Lock()

def sync(
    source: str,
    destinations: typing.List[str],
    excludes: typing.Optional[typing.List[str]] = None,
    daemon: typing.Optional[bool] = False,
) -> typing.Optional[threading.Thread]:
    if daemon:
        thread = threading.Thread(
            target=_sync,
            args=(source, destinations, excludes),
            daemon=True,
        )
        thread.start()
        return thread
    else:
        _sync(source, destinations, excludes)
        return None

def _glob_to_regex(core: str) -> str:
    i = 0
    out = []
    n = len(core)
    while i < n:
        c = core[i]

        if c == "*" and i + 2 <= n and core[i:i+3] == "**/":
            out.append(r"(?:[^/]*/)*")
            i += 3
            continue
        if c == "*" and i + 1 < n and core[i:i+2] == "**":
            out.append(r".*")
            i += 2
            continue
        if c == "*":
            out.append(r"[^/]*")
            i += 1
            continue
        if c == "?":
            out.append(r"[^/]")
            i += 1
            continue
        if c == "[":
            j = i + 1
            if j < n and core[j] == "!":
                j += 1
                negate = True
            else:
                negate = False
            content = []
            closed = False
            while j < n:
                ch = core[j]
                if ch == "]":
                    closed = True
                    j += 1
                    break
                content.append(ch)
                j += 1
            if not closed:
                out.append(re.escape("["))
                i += 1
            else:
                if negate:
                    out.append("[" + "^" + "".join(content) + "]")
                else:
                    out.append("[" + "".join(content) + "]")
                i = j
            continue

        out.append(re.escape(c))
        i += 1

    return "".join(out)

def _compile_pattern(pattern: str):
    anchored = pattern.startswith("/")
    dir_only = pattern.endswith("/")
    core = pattern[1:] if anchored else pattern
    if dir_only and core.endswith("/"):
        core = core[:-1]

    body = _glob_to_regex(core)
    exact_re = re.compile(r"^" + body + r"$")
    dir_re = re.compile(r"^" + body + r"(?:/.*)?$")

    def match(path: str) -> bool:
        relpath = path.lstrip("/")
        if anchored:
            if dir_only:
                return dir_re.match(relpath) is not None
            else:
                return exact_re.match(relpath) is not None

        parts = relpath.split("/") if relpath else [""]
        for i in range(len(parts)):
            suffix = "/".join(parts[i:])
            if exact_re.match(suffix):
                return True
            if dir_only and dir_re.match(suffix):
                return True
            if "/" in suffix:
                first, _ = suffix.split("/", 1)
                if exact_re.match(first):
                    return True
        return False

    return match

def _compile_patterns(patterns: typing.List[str]):
    matchers = []

    for pattern in patterns:
        matchers.append(_compile_pattern(pattern))

    def match_any(path: str) -> bool:
        for matcher in matchers:
            if matcher(path):
                return True
        return False

    return match_any

def _sync(
    source: str,
    destinations: typing.List[str],
    excludes: typing.Optional[typing.List[str]] = None,
) -> None:
    if excludes is None:
        excludes = []
    exclude_matcher = _compile_patterns(excludes)

    if not source.endswith("/"):
        print("Error: source must end in /")
        sys.exit(1)
    source = str(pathlib.Path(source).resolve()) + "/"

    for i, dest in enumerate(destinations):
        if not dest.endswith("/"):
            print("Error: destination must end in /")
            sys.exit(1)
        if ":" not in dest:
            print("Error: destination must be remote path")
            sys.exit(1)
        parts = dest.strip().split(":", 1)
        if len(parts) != 2:
            print("Error: destination path invalid")
            sys.exit(1)
        destinations[i] = f"{parts[0]}:{str(
            pathlib.Path(parts[1]).resolve())}/"

    print_lock.acquire()
    print("-------------------------Live Syncing-------------------------")
    print(f"Source: {source}")
    print(f"Destinations:")
    for dest in destinations:
        print(f"  {dest}")
    print(f"Excludes:")
    for exclude in excludes:
        print(f"  {exclude}")
    print("--------------------------------------------------------------")
    print_lock.release()

    inotify_cmd = [
        "inotifywait",
        "--recursive",
        "--monitor",
        "--event", "modify,create,delete,move",
        "--format", "%e %w%f",
        source,
    ]

    try:
        process = subprocess.Popen(
            inotify_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        for dest in destinations:
            _sync_once(source, dest, excludes, None)

        changes_set = set()
        last_sync = time.time()
        batch_delay = 0.3

        for line in process.stdout:
            if line.strip():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    event, filepath = parts
                    rel_path = filepath.replace(source, "", 1)
                    if rel_path:
                        changes_set.add((event, rel_path))

                current_time = time.time()
                if changes_set and (current_time - last_sync) >= batch_delay:
                    changes = []
                    for change in changes_set:
                        if "balancer" in change[1]:
                            continue
                        if exclude_matcher(change[1]):
                            continue
                        changes.append(change)

                    if changes:
                        for dest in destinations:
                            _sync_once(source, dest, excludes, changes)
                    changes_set = set()
                    last_sync = current_time
    except KeyboardInterrupt:
        print("\n\nStopping live sync")
        process.terminate()
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

def _sync_once(
    source: str,
    dest: str,
    exclude: typing.List[str],
    changes: typing.Optional[typing.List[typing.Tuple[str, str]]],
) -> bool:
    cmd = ["rsync", "-avz", "--delete"]

    for pattern in exclude:
        cmd.extend(["--exclude", pattern])

    filter_file = None
    if changes:
        try:
            filter_file = tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".txt")

            included_paths = set()
            for event, filepath in changes:
                included_paths.add(filepath)

                path_parts = pathlib.Path(filepath).parts
                for i in range(len(path_parts)):
                    parent = "/".join(path_parts[:i+1])
                    if parent and parent not in included_paths:
                        filter_file.write(f"+ /{parent}\n")
                        included_paths.add(parent)

                filter_file.write(f"+ /{filepath}\n")

            filter_file.write("- *\n")
            filter_file.close()
            cmd.extend(["--filter", f". {filter_file.name}"])

        except Exception as e:
            print(f"Warning: Could not create filter file: {e}")
            if filter_file:
                try:
                    pathlib.Path(filter_file.name).unlink()
                except:
                    pass
            filter_file = None

    cmd.extend([source, dest])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        if filter_file:
            try:
                pathlib.Path(filter_file.name).unlink()
            except:
                pass

        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            changes = [l for l in lines if l and not l.startswith("sending")
                and not l.startswith("sent") and not l.startswith("total")
                and not l.startswith("building")]
            if changes:
                print_lock.acquire()
                print("------------------------Changes Synced" +
                    "------------------------")
                print(f"Source: {source}")
                print(f"Destination: {dest}")
                for change in changes[:20]:
                    print(f"  {change}")
                if len(changes) > 20:
                    print(f"  ... {len(changes) - 20} more changes")
                print("-------------------------------" +
                    "-------------------------------")
                print_lock.release()

        return True
    except subprocess.CalledProcessError as e:
        print_lock.acquire()
        print(f"Sync failed: {e.stderr}")
        print_lock.release()
        if filter_file:
            try:
                pathlib.Path(filter_file.name).unlink()
            except:
                pass
        return False

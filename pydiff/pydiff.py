#!/usr/bin/env python3
"""Compare PyPI wheels or source distributions with the Python 3.9+ standard library.

Usage: python3 pydiff.py OLD.whl NEW.whl > changes.diff
       python3 pydiff.py 'reactivex==4.1.0' 'reactivex==6.0.0' > changes.diff
       python3 pydiff.py --sdist 'charset-normalizer==3.4.9' 'charset-normalizer==3.5.2'

PyPI inputs download archives into a temporary directory, verify their SHA-256
against PyPI's release metadata, compare them, then remove the downloads.
Default wheel-tag target: CPython 3.12, Linux (glibc), x86-64, regardless of the
Python running this script. Prefers cp312 native wheels, then compatible abi3
wheels, with pure-Python wheels as fallback. Among equal Python/ABI tags,
prefers manylinux's lowest glibc baseline, then generic linux_x86_64.
This selects artifacts for inspection, not an installation compatibility check;
Requires-Python/dependencies are not resolved. Override with --wheel-tag and a
Python/ABI/platform tag or glob (e.g. 'cp311-cp311-manylinux*x86_64').
With --sdist, download and compare the entire published source distributions,
including build configuration, in-tree backend code, and native sources if
included. Local source archives are also supported with --sdist. Normalize
the single top-level source folder. Symlink/hardlink targets are compared as
metadata and never followed; special devices and sparse tar files are rejected.
Unchanged files are counted but not printed. Build dependencies, external
backends, omitted repository files, and compiled-code provenance are not audited.
No pip, dependency installation, or build steps are involved.
Download progress goes to stderr; the comparison goes to stdout.

Reads archive members without extracting, importing, or executing their contents.
Wheel mode includes metadata and RECORD by default, matching versioned
.dist-info/.data roots. Archive timestamps/compression/order are ignored;
member bytes and Unix modes are compared. Non-UTF-8/NUL-containing files are
reported by size and SHA-256 instead of a line diff. Control characters other
than tabs/newlines are escaped for display (including CR as \\r).

Exit codes: 0 = identical compared contents, 1 = differences, 2 = error.
"""

import argparse
import difflib
import fnmatch
import hashlib
import http.client
import io
import json
import re
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from contextlib import ExitStack
from pathlib import Path


def validate_url(url, expected_host=None):
    parsed = urllib.parse.urlsplit(url)
    allowed = {expected_host} if expected_host else {"pypi.org", "files.pythonhosted.org"}
    if (parsed.scheme != "https" or parsed.hostname not in allowed
            or parsed.port not in (None, 443) or parsed.username or parsed.password):
        raise ValueError("unexpected download URL: " + quoted(url))


class PyPIRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url):
    validate_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "pydiff/4.0"})
    return urllib.request.build_opener(PyPIRedirectHandler()).open(request, timeout=30)


def project_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel_tag(filename):
    parts = filename[:-4].rsplit("-", 3)
    if len(parts) != 4 or not filename.endswith(".whl"):
        raise ValueError("invalid wheel filename: " + quoted(filename))
    return "-".join(parts[-3:])


def default_wheel_rank(filename):
    """Rank CPython 3.12 / glibc Linux x86-64 tags; None means no match."""
    python_tags, abi_tags, platform_tags = wheel_tag(filename).split("-")
    supported = [("cp312", "cp312"), ("cp312", "abi3"), ("cp312", "none")]
    supported += [("cp3" + str(minor), "abi3") for minor in range(11, 1, -1)]
    supported += [("py312", "none"), ("py3", "none")]
    supported += [("py3" + str(minor), "none") for minor in range(11, -1, -1)]
    priorities = {pair: index for index, pair in enumerate(supported)}
    ranks = []
    legacy = {"manylinux1_x86_64": (2, 5), "manylinux2010_x86_64": (2, 12),
              "manylinux2014_x86_64": (2, 17)}
    for python_tag in python_tags.split("."):
        for abi_tag in abi_tags.split("."):
            priority = priorities.get((python_tag, abi_tag))
            if priority is None:
                continue
            for platform in platform_tags.split("."):
                match = re.fullmatch(r"manylinux_(\d+)_(\d+)_x86_64", platform)
                if match:
                    platform_rank = (0, int(match[1]), int(match[2]))
                elif platform in legacy:
                    platform_rank = (0,) + legacy[platform]
                elif platform == "linux_x86_64":
                    platform_rank = (1, 0, 0)
                elif platform == "any" and abi_tag == "none":
                    platform_rank = (2, 0, 0)
                else:
                    continue
                ranks.append((priority,) + platform_rank)
    return min(ranks) if ranks else None


def select_wheel(files, tag_pattern):
    wheels = [item for item in files if item.get("packagetype") == "bdist_wheel"
              and isinstance(item.get("filename"), str) and item["filename"].endswith(".whl")]
    if not wheels:
        raise ValueError("this release has no .whl files on PyPI")
    for item in wheels:
        if not re.fullmatch(r"[A-Za-z0-9_.!+-]+\.whl", item["filename"]):
            raise ValueError("invalid wheel filename: " + quoted(item["filename"]))

    if tag_pattern:
        candidates = [item for item in wheels
                      if fnmatch.fnmatchcase(wheel_tag(item["filename"]), tag_pattern)]
    else:
        ranked = [(default_wheel_rank(item["filename"]), item) for item in wheels]
        ranked = [(rank, item) for rank, item in ranked if rank is not None]
        best_rank = min((rank for rank, _ in ranked), default=None)
        candidates = [item for rank, item in ranked if rank == best_rank]
        # Preserve the preference for a Python-3-only universal wheel.
        preferred = [item for item in candidates if wheel_tag(item["filename"]) == "py3-none-any"]
        if preferred:
            candidates = preferred
    if len(candidates) != 1:
        choices = "\n  ".join(sorted(item["filename"] for item in (candidates or wheels)))
        if not candidates:
            reason = ("no wheel matches --wheel-tag" if tag_pattern
                      else "no wheel matches Linux x86-64 / CPython 3.12 tags")
        else:
            reason = "multiple wheels match; selection is ambiguous"
        raise ValueError(reason + ". Use --wheel-tag or supply an exact local .whl. Available files:\n  " + choices)
    return candidates[0]


def select_sdist(files):
    sources = [item for item in files if item.get("packagetype") == "sdist"
               and isinstance(item.get("filename"), str)]
    if not sources:
        raise ValueError("this release has no source distribution on PyPI")
    for item in sources:
        if not re.fullmatch(r"[A-Za-z0-9_.!+-]+", item["filename"]):
            raise ValueError("invalid source archive filename: " + quoted(item["filename"]))
    for suffix in (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz", ".tar"):
        candidates = [item for item in sources if item["filename"].endswith(suffix)]
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            raise ValueError("multiple source distributions match; supply exact local archives")
    raise ValueError("unsupported source archive format; expected tar or ZIP")


def download_target(value, side, temporary_directory, args):
    # Existing paths take precedence, including unusual names containing '=='.
    if Path(value).is_file() or "==" not in value:
        return Path(value)
    match = re.fullmatch(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)", value)
    if not match:
        raise ValueError("expected a local archive path or an exact package==version: " + quoted(value))
    name, version = match.groups()
    url = "https://pypi.org/pypi/" + urllib.parse.quote(name, safe="") + "/" + urllib.parse.quote(version, safe="") + "/json"
    print("Fetching PyPI metadata for " + quoted(value), file=sys.stderr)
    try:
        with open_url(url) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError("PyPI project/version not found: " + quoted(value)) from exc
        raise
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("PyPI metadata exceeds 8 MiB")
    metadata = json.loads(raw)
    if not isinstance(metadata, dict) or not isinstance(metadata.get("urls"), list):
        raise ValueError("invalid PyPI release metadata")
    info = metadata.get("info") or {}
    if not isinstance(info, dict) or project_name(str(info.get("name", ""))) != project_name(name):
        raise ValueError("PyPI response project name does not match the requested package")
    if any(not isinstance(item, dict) for item in metadata["urls"]):
        raise ValueError("invalid PyPI file metadata")
    selected = (select_sdist(metadata["urls"]) if args.sdist
                else select_wheel(metadata["urls"], args.wheel_tag))
    filename = selected["filename"]
    digests = selected.get("digests")
    if not isinstance(digests, dict):
        raise ValueError("PyPI did not supply hash metadata for " + quoted(filename))
    expected_hash = digests.get("sha256", "")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
        raise ValueError("PyPI did not supply a valid SHA-256 for " + quoted(filename))
    download_url = selected.get("url")
    if not isinstance(download_url, str):
        raise ValueError("PyPI did not supply an archive URL")
    validate_url(download_url, "files.pythonhosted.org")
    maximum = args.max_download_mib * 1024 * 1024
    expected_size = selected.get("size")
    if isinstance(expected_size, int) and expected_size > maximum:
        raise ValueError("archive exceeds --max-download-mib: " + quoted(filename))
    if selected.get("yanked"):
        print("Yanked PyPI file: " + quoted(filename) + "; reason="
              + quoted(selected.get("yanked_reason") or "unspecified"), file=sys.stderr)
    print("Downloading " + quoted(filename) + " (uploaded "
          + quoted(selected.get("upload_time_iso_8601") or "unknown") + ")", file=sys.stderr)
    destination = Path(temporary_directory) / side / filename
    destination.parent.mkdir()
    digest = hashlib.sha256()
    total = 0
    with open_url(download_url) as response, destination.open("xb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("download exceeds --max-download-mib")
            digest.update(chunk)
            output.write(chunk)
    if isinstance(expected_size, int) and total != expected_size:
        raise ValueError("download size does not match PyPI metadata for " + quoted(filename))
    if digest.hexdigest() != expected_hash.lower():
        raise ValueError("download SHA-256 does not match PyPI metadata for " + quoted(filename))
    print("Verified SHA-256: " + digest.hexdigest(), file=sys.stderr)
    return destination


def visible(text):
    """Keep terminal escapes and invisible formatting characters visible."""
    return "".join(
        char if char.isprintable() or char in "\n\t" else ascii(char)[1:-1]
        for char in text
    )


def quoted(text):
    return json.dumps(str(text), ensure_ascii=True)


class SdistArchive:
    """Expose tar or ZIP source members through the comparator's ZIP-like API."""

    def __init__(self, path, max_bytes):
        self.path = path
        self.max_bytes = max_bytes
        self.archive = None
        self.members = []
        self.tar_members = {}
        self.is_zip = False

    def __enter__(self):
        if self.path.suffix == ".whl":
            raise ValueError("--sdist expects source archives, not .whl files")
        try:
            self.is_zip = zipfile.is_zipfile(self.path)
            if self.is_zip:
                self.archive = zipfile.ZipFile(self.path)
                self.members = self.archive.infolist()
                return self
            self.archive = tarfile.open(self.path, "r:*")
            for raw in self.archive:
                if raw.sparse is not None:
                    raise ValueError("unsupported sparse tar member: " + quoted(raw.name))
                if raw.isdir():
                    kind, mode = "directory", stat.S_IFDIR
                elif raw.isreg():
                    kind, mode = "file", stat.S_IFREG
                elif raw.issym():
                    kind, mode = "symlink", stat.S_IFLNK
                elif raw.islnk():
                    kind, mode = "hardlink", stat.S_IFREG
                else:
                    raise ValueError("unsupported special tar member: " + quoted(raw.name))
                if raw.size > self.max_bytes:
                    raise ValueError(quoted(raw.name) + " exceeds --max-file-mib")
                name = raw.name.rstrip("/") + "/" if raw.isdir() else raw.name
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (mode | (raw.mode & 0o7777)) << 16
                member.file_size = (len(raw.linkname.encode("utf-8", "surrogateescape"))
                                    if kind in ("symlink", "hardlink") else raw.size)
                # ZipInfo is slotted; keep tar-specific metadata in this mapping.
                self.members.append(member)
                self.tar_members[member] = raw
            return self
        except Exception:
            if self.archive is not None:
                self.archive.close()
            raise

    def __exit__(self, *_):
        if self.archive is not None:
            self.archive.close()

    def infolist(self):
        return self.members

    def open(self, member):
        if self.is_zip:
            return self.archive.open(member)
        raw = self.tar_members[member]
        if raw.issym() or raw.islnk():
            # Read the stored target name only: extractfile() would follow links.
            return io.BytesIO(raw.linkname.encode("utf-8", "surrogateescape"))
        if not raw.isreg():
            raise ValueError("cannot read nonregular source member: " + quoted(raw.name))
        return self.archive.extractfile(raw)

    def kind(self, member):
        if member is None:
            return "absent"
        if not self.is_zip and self.tar_members[member].islnk():
            return "hardlink"
        mode = unix_mode(member)
        return "symlink" if mode is not None and stat.S_ISLNK(mode) else "file"


def index_sdist(archive):
    entries = []
    names = set()
    roots = set()
    for member in archive.infolist():
        name = member.orig_filename
        if "\0" in name or "\\" in name or name.startswith("/"):
            raise ValueError("unsafe source archive path: " + quoted(name))
        while name.startswith("./"):
            name = name[2:]
        if member.is_dir():
            name = name.rstrip("/")
        parts = name.split("/")
        if any(part in ("", ".", "..") for part in parts) or ":" in parts[0]:
            raise ValueError("unsafe source archive path: " + quoted(name))
        if name in names:
            raise ValueError("duplicate source archive path: " + quoted(name))
        names.add(name)
        roots.add(parts[0])
        if member.is_dir():
            continue
        mode = unix_mode(member)
        if mode is not None and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFLNK):
            raise ValueError("unsupported special source member: " + quoted(name))
        if len(parts) < 2:
            raise ValueError("source archive must contain a single top-level directory")
        entries.append(("/".join(parts[1:]), member))
    if len(roots) != 1 or not entries:
        raise ValueError("source archive must contain a single nonempty top-level directory")
    return dict(entries)


def index_wheel(archive, ignore_record):
    members = archive.infolist()
    names = set()
    roots = set()
    for member in members:
        name = member.filename
        if name in names:
            raise ValueError("duplicate ZIP member: " + quoted(name))
        names.add(name)
        root, separator, _ = name.partition("/")
        if separator and root.endswith(".dist-info"):
            roots.add(root)

    if len(roots) != 1:
        raise ValueError("expected exactly one top-level .dist-info directory")
    metadata_root = roots.pop()
    for required in ("METADATA", "WHEEL", "RECORD"):
        if metadata_root + "/" + required not in names:
            raise ValueError("missing wheel metadata file: " + required)
    data_root = metadata_root[:-len(".dist-info")] + ".data"

    indexed = {}
    for member in members:
        if member.is_dir():
            continue
        name = member.filename
        root, separator, tail = name.partition("/")
        if separator and root == metadata_root:
            if ignore_record and tail == "RECORD":
                continue
            key = "{dist-info}/" + tail
        elif separator and root == data_root:
            key = "{data}/" + tail
        else:
            key = name
        if key in indexed:
            raise ValueError("ambiguous normalized path: " + quoted(key))
        indexed[key] = member
    return indexed


def read_member(archive, member, max_bytes):
    if member is None:
        return b""
    if member.file_size > max_bytes:
        raise ValueError(
            quoted(member.filename) + " exceeds --max-file-mib; raise the limit to compare it"
        )
    with archive.open(member) as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("decompressed member exceeds --max-file-mib")
    return data


def text_lines(data):
    if b"\0" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Split only on LF; preserve CR, trailing newlines, and every other byte.
    chunks = text.split("\n")
    return [line + "\n" for line in chunks[:-1]] + ([chunks[-1]] if chunks[-1] else [])


def unix_mode(member):
    if member is None or member.create_system != 3:
        return None
    return (member.external_attr >> 16) & 0xFFFF


def describe_mode(member):
    mode = unix_mode(member)
    return "unspecified" if mode is None else format(mode, "06o")


def label(side, member):
    return "/dev/null" if member is None else quoted(side + "/" + member.filename)


def print_change(key, old_member, new_member, old_data, new_data, context,
                 old_kind="file", new_kind="file"):
    status = "added" if old_member is None else "removed" if new_member is None else "modified"
    print("\n=== " + status + ": " + quoted(key) + " ===")
    for side, member, data, kind in (("old", old_member, old_data, old_kind),
                                    ("new", new_member, new_data, new_kind)):
        if member is not None:
            print(
                side + ": " + quoted(member.filename)
                + " | bytes=" + str(len(data))
                + " | sha256=" + hashlib.sha256(data).hexdigest()
                + " | unix-mode=" + describe_mode(member)
                + (" | kind=" + kind + "; bytes/hash describe the stored link target"
                   if kind in ("symlink", "hardlink") else "")
            )
    if old_member is not None and new_member is not None:
        if old_kind != new_kind:
            print("Type: " + old_kind + " -> " + new_kind)
        if unix_mode(old_member) != unix_mode(new_member):
            print("Unix mode: " + describe_mode(old_member) + " -> " + describe_mode(new_member))
        if old_data == new_data:
            return

    old_lines, new_lines = text_lines(old_data), text_lines(new_data)
    if old_lines is None or new_lines is None:
        print("Binary/non-UTF-8 file " + status + "; see sizes and SHA-256 hashes above.")
        return
    if not old_data and not new_data:
        print("Empty file " + status + ".")
        return
    for line in difflib.unified_diff(
        old_lines, new_lines,
        fromfile=label("old", old_member), tofile=label("new", new_member), n=context,
    ):
        sys.stdout.write(visible(line))
        if not line.endswith("\n"):
            sys.stdout.write("\n\\ No newline at end of file\n")


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", help="older local archive or package==version")
    parser.add_argument("new", help="newer local archive or package==version")
    parser.add_argument("--sdist", action="store_true", help="compare full source distributions, including build hooks")
    parser.add_argument("--wheel-tag", help="override default Linux x86-64 / CPython 3.12 wheel tags with a tag/glob")
    parser.add_argument("--max-download-mib", type=positive, default=256,
                        help="maximum archive download size (default: 256 MiB)")
    parser.add_argument("-U", "--context", type=nonnegative, default=3, help="context lines (default: 3)")
    parser.add_argument("--ignore-record", action="store_true", help="omit .dist-info/RECORD only")
    parser.add_argument("--max-file-mib", type=positive, default=256,
                        help="maximum decompressed size per member; errors if exceeded (default: 256 MiB)")
    args = parser.parse_args()
    if args.sdist and (args.wheel_tag or args.ignore_record):
        parser.error("--sdist cannot be combined with --wheel-tag or --ignore-record")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    counts = {"added": 0, "removed": 0, "modified": 0, "unchanged": 0}
    try:
        with tempfile.TemporaryDirectory(prefix="pydiff-") as temporary_directory:
            old_path = download_target(args.old, "old", temporary_directory, args)
            new_path = download_target(args.new, "new", temporary_directory, args)
            return compare_archives(old_path, new_path, args, counts)
    except (OSError, ValueError, http.client.HTTPException, zipfile.BadZipFile,
            tarfile.TarError, zlib.error, RuntimeError, NotImplementedError, EOFError) as exc:
        print("pydiff: comparison incomplete: " + visible(str(exc)), file=sys.stderr)
        return 2


def compare_archives(old_path, new_path, args, counts):
    with ExitStack() as stack:
        old_zip = stack.enter_context(SdistArchive(old_path, args.max_file_mib * 1024 * 1024)
                                      if args.sdist else zipfile.ZipFile(old_path))
        new_zip = stack.enter_context(SdistArchive(new_path, args.max_file_mib * 1024 * 1024)
                                      if args.sdist else zipfile.ZipFile(new_path))
        old_index = index_sdist(old_zip) if args.sdist else index_wheel(old_zip, args.ignore_record)
        new_index = index_sdist(new_zip) if args.sdist else index_wheel(new_zip, args.ignore_record)
        print("# Old input: " + quoted(args.old))
        print("# New input: " + quoted(args.new))
        print("# Old archive: " + quoted(old_path.name))
        print("# New archive: " + quoted(new_path.name))
        if args.sdist:
            print("# Source-distribution comparison: all source files and build configuration.")
            print("# Single top-level source folders are normalized; links are not followed.")
        elif "==" in args.old or "==" in args.new:
            print("# Download wheel-tag target: " + (quoted(args.wheel_tag) if args.wheel_tag
                  else "CPython 3.12 / Linux glibc / x86-64"))
        if not args.sdist:
            print("# Versioned .dist-info/.data roots are matched across versions.")
        if args.ignore_record:
            print("# RECORD excluded by --ignore-record.")
        for key in sorted(old_index.keys() | new_index.keys()):
            old_member, new_member = old_index.get(key), new_index.get(key)
            old_data = read_member(old_zip, old_member, args.max_file_mib * 1024 * 1024)
            new_data = read_member(new_zip, new_member, args.max_file_mib * 1024 * 1024)
            old_kind = old_zip.kind(old_member) if args.sdist else "file"
            new_kind = new_zip.kind(new_member) if args.sdist else "file"
            if old_member is not None and new_member is not None:
                if (old_data == new_data and unix_mode(old_member) == unix_mode(new_member)
                        and old_kind == new_kind):
                    counts["unchanged"] += 1
                    continue
                status = "modified"
            else:
                status = "added" if old_member is None else "removed"
            counts[status] += 1
            print_change(key, old_member, new_member, old_data, new_data, args.context, old_kind, new_kind)
    print("\nSummary: " + ", ".join(str(counts[k]) + " " + k for k in counts), file=sys.stderr)
    return int(any(counts[k] for k in ("added", "removed", "modified")))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Allow piping to tools that close early, e.g. `head`.
        import os
        os._exit(0)

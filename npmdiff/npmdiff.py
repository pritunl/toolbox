#!/usr/bin/env python3
"""Download and diff two exact public npm releases. Python 3.9+, no dependencies.

Examples:
    python3 npmdiff.py fast-uri==3.1.4 fast-uri==3.1.9
    python3 npmdiff.py @xmldom/xmldom==0.8.13 @xmldom/xmldom==0.8.15
    python3 npmdiff.py moment==2.30.1 moment==2.31.0 --exclude '*.map'

Diff goes to stdout; progress goes to stderr. Exit codes: 0 identical,
1 differences found, 2 error, 130 interrupted, 141 closed output pipe.
No package code or installation hooks are run.
Archives are read in memory, never extracted to the filesystem. npm's digest
is verified, but that is not proof that a package is trustworthy.
Limits per release: 128 MiB downloaded, 512 MiB unpacked, 100,000 archive entries.
This is a review display, not a directly applicable patch: backslashes, tabs,
CR, control/format characters and invalid UTF-8 bytes are visibly escaped.
All changed contents are shown, including files containing NUL bytes.
Malformed/ambiguous tar layouts and unsupported extended metadata are rejected;
the script will not silently compare just the readable prefix of an archive.
"""

import argparse
import base64
import difflib
import fnmatch
import gzip
import hashlib
import hmac
import http.client
import io
import json
import math
import os
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


REGISTRY = "https://registry.npmjs.org"
MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_UNPACKED = 512 * 1024 * 1024
MAX_MEMBERS = 100_000


class DiffError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    kind: str
    mode: int
    data: bytes


def parse_spec(value):
    name, separator, version = value.partition("==")
    if not separator or not re.fullmatch(
        r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+", name
    ) or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
    ):
        raise argparse.ArgumentTypeError(
            "expected package==exact.version, e.g. fast-uri==3.1.9 "
            "or @xmldom/xmldom==0.8.15"
        )
    return name, version


class RegistryOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        check_url(newurl)
        return super().redirect_request(
            request, response, code, message, headers, newurl
        )


def check_url(url):
    if not isinstance(url, str) or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise DiffError("invalid download URL")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org"
            or parsed.port not in (None, 443) or parsed.username is not None
            or parsed.password is not None):
        raise DiffError("refusing a download outside https://registry.npmjs.org")


def download(url, timeout, limit=MAX_DOWNLOAD):
    check_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "npmdiff/1.0"})
    opener = urllib.request.build_opener(RegistryOnlyRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            chunks, size = [], 0
            while True:
                chunk = response.read(min(1024 * 1024, limit - size + 1))
                if not chunk:
                    return b"".join(chunks)
                size += len(chunk)
                if size > limit:
                    raise DiffError(f"download exceeds {limit // 1024 // 1024} MiB")
                chunks.append(chunk)
    except urllib.error.HTTPError as exc:
        raise DiffError(f"HTTP {exc.code} downloading {url}") from exc
    except urllib.error.URLError as exc:
        raise DiffError(f"download failed: {exc.reason}") from exc


def verify_integrity(blob, dist):
    integrity = dist.get("integrity")
    if integrity is not None and not isinstance(integrity, str):
        raise DiffError("npm integrity metadata must be a string")
    if integrity:
        # For multiple SRI digests, require a match at the strongest algorithm.
        for algorithm in ("sha512", "sha384", "sha256", "sha1"):
            expected = [token.split("-", 1)[1].split("?", 1)[0]
                        for token in integrity.split()
                        if token.startswith(algorithm + "-")]
            if expected:
                actual = base64.b64encode(
                    hashlib.new(algorithm, blob).digest()
                ).decode("ascii")
                if not any(hmac.compare_digest(actual, digest) for digest in expected):
                    raise DiffError(f"{algorithm} integrity verification failed")
                return
        raise DiffError("npm metadata has no supported integrity algorithm")
    # Old releases may only have npm's legacy SHA-1 digest.
    expected = dist.get("shasum")
    if not isinstance(expected, str) or not hmac.compare_digest(
        hashlib.sha1(blob).hexdigest(), expected.lower()
    ):
        raise DiffError("missing or mismatched npm SHA-1 digest")


class BoundedReader:
    """Bound all decompressed bytes, including tar headers and ignored files."""

    def __init__(self, source):
        self.source = source
        self.remaining = MAX_UNPACKED

    def read(self, size=-1):
        size = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.source.read(size)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise DiffError("unpacked archive exceeds 512 MiB")
        return data


def parse_pax(data):
    """Accept unambiguous POSIX records, not tarfile's permissive partial parse."""
    result, position = {}, 0
    allowed = {"path", "linkpath", "size", "uid", "gid", "uname", "gname",
               "mtime", "atime", "ctime", "charset", "hdrcharset", "comment",
               "SCHILY.dev", "SCHILY.ino", "SCHILY.nlink"}
    while position < len(data):
        separator = data.find(b" ", position)
        length_field = data[position:separator] if separator >= 0 else b""
        if not length_field.isdigit() or length_field.startswith(b"0"):
            raise DiffError("malformed PAX record length")
        length = int(length_field)
        end = position + length
        if end > len(data) or end <= separator + 2 or data[end - 1:end] != b"\n":
            raise DiffError("truncated or malformed PAX record")
        key, equals, value = data[separator + 1:end - 1].partition(b"=")
        if not equals or not key or b"\0" in key + value:
            raise DiffError("malformed PAX key/value")
        key, value = key.decode("utf-8"), value.decode("utf-8")
        if key not in allowed:
            raise DiffError(f"unsupported PAX metadata: {key!r}")
        if key in result:
            raise DiffError(f"duplicate PAX field: {key!r}")
        if key in ("path", "linkpath") and not value:
            raise DiffError(f"empty PAX field: {key!r}")
        if key == "size" and not re.fullmatch(r"[0-9]+", value):
            raise DiffError("invalid PAX size")
        if key in ("charset", "hdrcharset") and value not in (
                "UTF-8", "ISO-IR 10646 2000 UTF-8"):
            raise DiffError("unsupported PAX character encoding")
        result[key] = value
        position = end
    return result


def validate_tar(raw):
    """Reject any archive for which a permissive parser could see extra entries.

    Python tarfile can stop silently at one zero block or an invalid later
    header. Validate all physical headers and the complete trailer before
    letting it interpret supported PAX/GNU metadata. Ambiguous extensions are
    rejected rather than claiming exact parity with every npm tar parser.
    """
    if len(raw) % 512:
        raise DiffError("tar archive has a truncated block")
    position, count, extension_chain = 0, 0, 0
    expected, pending, long_fields = [], None, set()
    regular = (tarfile.REGTYPE, tarfile.AREGTYPE)
    ordinary = regular + (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE)
    extensions = (tarfile.XHDTYPE, tarfile.XGLTYPE,
                  tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
    while position < len(raw):
        header = raw[position:position + 512]
        if header == bytes(512):
            if pending is not None or long_fields:
                raise DiffError("tar ends with unapplied extended metadata")
            trailer = memoryview(raw)[position:]
            if len(trailer) < 1024 or any(trailer):
                raise DiffError("tar has a lone zero block or nonzero data after its terminator")
            return expected
        count += 1
        if count > MAX_MEMBERS:
            raise DiffError("archive contains too many entries")
        try:
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
            raise DiffError(f"invalid tar header at byte {position}: {exc}") from exc
        if member.type not in ordinary + extensions or member.issparse():
            raise DiffError(f"unsupported tar entry type: {member.type!r}")
        extension_chain = extension_chain + 1 if member.type in extensions else 0
        if extension_chain > 8:
            raise DiffError("too many consecutive tar extension headers")
        if member.size < 0 or member.size > MAX_UNPACKED:
            raise DiffError("invalid or oversized tar member")
        body = position + 512
        next_header = body + ((member.size + 511) // 512) * 512
        if next_header > len(raw):
            raise DiffError(f"truncated tar member: {member.name!r}")
        if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            if pending is not None or long_fields:
                raise DiffError("ambiguous stacked tar extension headers")
            fields = parse_pax(raw[body:body + member.size])
            if member.type == tarfile.XGLTYPE:
                if any(key in fields for key in ("path", "linkpath", "size")):
                    raise DiffError("global PAX path/linkpath/size is unsupported")
            else:
                pending = fields
        elif member.type in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            if pending is not None or member.type in long_fields:
                raise DiffError("ambiguous stacked tar extension headers")
            payload = raw[body:body + member.size]
            value, nul, trailing = payload.partition(b"\0")
            if not value or not nul or any(trailing):
                raise DiffError("malformed GNU long-name/link record")
            value.decode("utf-8", "strict")
            long_fields.add(member.type)
        else:
            if member.type not in regular and member.size != 0:
                raise DiffError("non-file tar entry has a nonzero payload size")
            if pending is not None and "size" in pending:
                # Small npm files do not need contradictory legacy/PAX sizes.
                # Different consumers disagree on which size frames the body.
                if int(pending["size"]) != member.size:
                    raise DiffError("conflicting PAX and tar-header member sizes")
            expected.append((body, member.size))
            pending, long_fields = None, set()
        position = next_header
    raise DiffError("tar archive is missing its two-zero-block terminator")


def read_archive(blob, excludes):
    entries, seen = {}, set()
    # Consume the whole gzip stream, including all members and CRC/footer.
    # Stopping at tar EOF would leave corrupt/compressed trailing data unchecked.
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as compressed:
        bounded = BoundedReader(compressed)
        with io.BytesIO() as unpacked:
            while True:
                chunk = bounded.read(1024 * 1024)
                if not chunk:
                    break
                unpacked.write(chunk)
            raw = unpacked.getvalue()
    expected = validate_tar(raw)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8",
                      errors="strict") as archive:
        count = 0
        for member in archive:
            if count >= len(expected) or (member.offset_data, member.size) != expected[count]:
                raise DiffError("tar parser disagrees with validated member boundaries")
            count += 1
            if member.name.startswith("/"):
                raise DiffError(f"absolute archive path: {member.name!r}")
            parts = [part for part in member.name.split("/") if part not in ("", ".")]
            if ".." in parts:
                raise DiffError(f"unsafe archive path: {member.name!r}")
            if parts and parts[0] == "package":
                parts = parts[1:]
            path = "/".join(parts)
            if member.isdir():
                continue
            if not path or path in seen:
                raise DiffError(f"empty or duplicate archive path: {path!r}")
            seen.add(path)
            if member.isreg() and not member.issparse():
                kind = "file"
                stream = archive.extractfile(member)  # Reads bytes; never writes a file.
                with stream:
                    data = stream.read()
                if len(data) != member.size:
                    raise DiffError(f"truncated file: {path!r}")
            elif member.issym() or member.islnk():
                kind = "symlink" if member.issym() else "hardlink"
                # Describe links; never follow them.
                data = (json.dumps(member.linkname, ensure_ascii=True) + "\n").encode()
            else:
                raise DiffError(f"unsupported archive entry: {path!r}")
            if not any(fnmatch.fnmatchcase(path, pattern) for pattern in excludes):
                entries[path] = Entry(kind, member.mode & 0o7777, data)
        if count != len(expected):
            raise DiffError("tar parser stopped before all validated entries were read")
    return entries


def fetch_package(spec, timeout, excludes):
    name, version = spec
    print(f"Downloading {name}=={version} ...", file=sys.stderr)
    metadata_url = (REGISTRY + "/" + urllib.parse.quote(name, safe="@")
                    + "/" + urllib.parse.quote(version, safe=""))
    metadata = json.loads(download(metadata_url, timeout, 8 * 1024 * 1024))
    if not isinstance(metadata, dict):
        raise DiffError("registry metadata must be a JSON object")
    if metadata.get("name") != name or metadata.get("version") != version:
        raise DiffError(f"registry did not return the exact requested release: {spec!r}")
    dist = metadata.get("dist")
    if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
        raise DiffError("registry metadata is missing a valid dist.tarball")
    blob = download(dist["tarball"], timeout)
    verify_integrity(blob, dist)
    entries = read_archive(blob, excludes)
    print(f"Verified {name}=={version}: {len(entries)} files/links", file=sys.stderr)
    return entries


def text_lines(data):
    # Preserve every input byte. Render escapes only AFTER computing the diff.
    text = data.decode("utf-8", errors="surrogateescape")
    # Split only at LF, preserving CRLF and missing final newlines.
    lines = text.split("\n")
    return [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def visible(text, keep_final_newline=False):
    """Unambiguous, terminal-safe display of decoded content and diagnostics."""
    result = []
    for index, char in enumerate(text):
        code = ord(char)
        if char == "\n" and keep_final_newline and index == len(text) - 1:
            result.append(char)
        elif char == "\\":
            result.append("\\\\")
        elif 0xDC80 <= code <= 0xDCFF:
            result.append(f"\\x{code - 0xDC00:02x}")  # Undecodable original byte.
        elif char in "\t\r\n":
            result.append({"\t": "\\t", "\r": "\\r", "\n": "\\n"}[char])
        elif code < 32 or code == 127:
            result.append(f"\\x{code:02x}")
        elif 128 <= code < 160 or unicodedata.category(char) in (
            "Cf", "Co", "Cn", "Cs", "Zl", "Zp"
        ) or (unicodedata.category(char) == "Zs" and char != " "):
            # Keep valid Unicode C1 distinct from surrogateescaped raw bytes.
            result.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            result.append(char)
    return "".join(result)


def label(value):
    return json.dumps(value, ensure_ascii=True) if any(
        char.isspace() or char in '\\"' or not char.isascii() or ord(char) < 32
        or ord(char) == 127 for char in value
    ) else value


def print_diff(old, new, old_spec, new_spec, context):
    changed = 0
    for path in sorted(old.keys() | new.keys()):
        before, after = old.get(path), new.get(path)
        if before == after:
            continue
        changed += 1
        old_path = label(f"{old_spec}/{path}")
        new_path = label(f"{new_spec}/{path}")
        print(f"diff --npm {old_path} {new_path}")
        if before is None:
            print(f"new {after.kind} mode {after.mode:04o}")
        elif after is None:
            print(f"deleted {before.kind} mode {before.mode:04o}")
        else:
            if before.kind != after.kind:
                print(f"type changed: {before.kind} -> {after.kind}")
            if before.mode != after.mode:
                print(f"old mode {before.mode:04o}\nnew mode {after.mode:04o}")
        left = before.data if before else b""
        right = after.data if after else b""
        if left == right:
            continue  # Mode/type-only change, or an added/deleted empty file.
        if b"\x00" in left or b"\x00" in right:
            print("NOTE: NUL-containing contents; full escaped diff follows.")
            for side, entry in (("old", before), ("new", after)):
                if entry is not None:
                    print(f"  {side}: {len(entry.data)} bytes, "
                          f"sha256={hashlib.sha256(entry.data).hexdigest()}")
        lines = difflib.unified_diff(
            text_lines(left), text_lines(right),
            fromfile=old_path if before else "/dev/null",
            tofile=new_path if after else "/dev/null", n=context,
        )
        for index, line in enumerate(lines):
            # The first two lines are headers with already-escaped path labels.
            # Hunk markers are ASCII. Escape every file-content line.
            rendered = line if index < 2 or line.startswith("@@ ") else visible(
                line, keep_final_newline=True
            )
            sys.stdout.write(rendered)
            if not line.endswith("\n"):
                sys.stdout.write("\n\\ No newline at end of file\n")
    return changed


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("old", type=parse_spec, help="old package==version")
    parser.add_argument("new", type=parse_spec, help="new package==version")
    parser.add_argument("-U", "--context", type=int, default=3, help="context lines (default: 3)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip matching package-relative paths; repeatable")
    parser.add_argument("--timeout", type=float, default=60, help="network timeout in seconds")
    args = parser.parse_args(argv)
    if args.context < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("context must be nonnegative and timeout must be finite and positive")
    if args.old[0] != args.new[0]:
        parser.error("both versions must refer to the same package")
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            jobs = [executor.submit(fetch_package, spec, args.timeout, args.exclude)
                    for spec in (args.old, args.new)]
            old, new = [job.result() for job in jobs]
        changed = print_diff(old, new, "==".join(args.old), "==".join(args.new), args.context)
        print(f"{changed} changed file(s)/link(s).", file=sys.stderr)
        return int(bool(changed))
    except BrokenPipeError:
        raise
    except (DiffError, OSError, EOFError, tarfile.TarError, ValueError,
            KeyError, TypeError, OverflowError, zlib.error, http.client.HTTPException) as exc:
        print(f"npmdiff: {visible(str(exc))}", file=sys.stderr)
        return 2


def run_cli():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace", newline="")
        status = main()
        # Catch a broken pipe even when the entire diff fits in Python's buffer.
        sys.stdout.flush()
        return status
    except BrokenPipeError:
        # Redirect the underlying descriptor, not just the Python object: this
        # prevents a second failure when the buffered stream is finalized.
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        return 141
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(run_cli())

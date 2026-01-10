#!/usr/bin/env python3
import sys
import os
import datetime
import hashlib
import hmac
import time
import json
import getpass
import http.client
import urllib.parse
import xml.etree.ElementTree

content_types = {
    ".html": "text/html",
    ".htm": "text/html",
    ".xhtml": "application/xhtml+xml",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".xml": "application/xml",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".tar": "application/x-tar",
    ".rar": "application/vnd.rar",
    ".7z": "application/x-7z-compressed",
    ".bz2": "application/x-bzip2",
    ".zst": "application/zstd",
    ".xz": "application/x-xz",
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
    ".so": "application/octet-stream",
    ".apk": "application/vnd.android.package-archive",
    ".deb": "application/vnd.debian.binary-package",
    ".rpm": "application/x-rpm",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".sig": "application/pgp-signature",
    ".asc": "application/pgp-signature",
    ".py": "text/x-python",
    ".go": "text/x-go",
    ".sh": "application/x-sh",
}

def print_help():
    program_name = os.path.basename(sys.argv[0])
    print(f"""{program_name} - transfers files with S3-compatible storage

Usage: {program_name} [OPTIONS] cp SOURCE DESTINATION
  or   {program_name} [OPTIONS] ls PROVIDER:[PATH]
  or   {program_name} [OPTIONS] rm PROVIDER:/PATH
  or   {program_name} [OPTIONS] mirror [--remove] LOCAL_DIR PROVIDER:/PATH
  or   {program_name} [OPTIONS] add-provider
  or   {program_name} --help

DESCRIPTION
    Dependency-free tool for uploading and downloading files to/from
    S3-compatible storage services. Implements AWS Signature Version 4
    authentication.

COMMANDS
    cp SOURCE DESTINATION
        Copy files between local filesystem and S3-compatible storage.

        Upload:   {program_name} cp ./file.tar provider:/path/file.tar
        Download: {program_name} cp provider:/path/file.tar ./file.tar

    ls PROVIDER:[PATH]
        List objects in S3-compatible storage

        List bucket: {program_name} ls provider:
        List folder: {program_name} ls provider:/folder/

    rm PROVIDER:/PATH
        Remove object from S3-compatible storage.

        Remove file: {program_name} rm provider:/path/file.tar

    mirror [--remove] [--overwrite] LOCAL_DIR PROVIDER:/PATH
        Mirror a local directory to S3, syncing based on modification times.
        Files are uploaded if they don't exist on S3 or local modification
        time is newer than S3 modification time. Files are skipped if S3
        modification time is equal to or newer than local modification time.

        --remove: Delete files on S3 that don't exist locally
        --overwrite: Upload all files regardless of modification time

        Example: {program_name} mirror ./dist/ provider:/website/
                 {program_name} mirror --remove ./dist/ provider:/website/
                 {program_name} mirror --overwrite ./dist/ provider:/website/

    add-provider
        Interactively add a new provider configuration.

OPTIONS
    --config, -c PATH
        Path to configuration file (default: ~/.config/s3c.conf)

    --help, -h
        Display this help message and exit

CONFIGURATION FILE
    Configuration is stored in JSON format at ~/.config/s3c.conf by default.

    Example configuration:
    {{
        "providers": {{
            "my-aws": {{
                "bucket": "my-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI...",
                "region": "us-east-1",
                "storage_class": "STANDARD_IA"
            }},
            "my-r2": {{
                "bucket": "r2-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI...",
                "cloudflare_account_id": "a8f2b4e6d9c1f7a3..."
            }},
            "my-oracle": {{
                "bucket": "oracle-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI...",
                "oracle_cloud_namespace": "ocidev"
            }},
            "my-vultr": {{
                "bucket": "vultr-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI...",
                "domain": "ewr2.vultrobjects.com"
            }}
        }}
    }}

ENVIRONMENT VARIABLES (Fallback)
    Authentication (Required):
        S3_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID
            Access key ID for authentication.

        S3_SECRET_ACCESS_KEY, AWS_SECRET_ACCESS_KEY
            Secret access key for authentication.

    Configuration (Optional):
        S3_REGION, AWS_DEFAULT_REGION
            Region for the S3 service (default: us-east-1)

        S3_STORAGE_CLASS, AWS_S3_STORAGE_CLASS
            Storage class for uploaded objects (e.g., STANDARD,STANDARD_IA,
            GLACIER, GLACIER_IR, DEEP_ARCHIVE)

        S3_BASE_DOMAIN, AWS_S3_BASE_DOMAIN
            Custom S3-compatible base service domain (e.g., s3.example.com)

    Provider-Specific:
        S3_CLOUDFLARE_ACCOUNT_ID
            Cloudflare R2 account ID. When set, uses R2 endpoints:
            BUCKET.ACCOUNT_ID.r2.cloudflarestorage.com

        S3_ORACLE_CLOUD_NAMESPACE
            Oracle Cloud namespace. When set, uses Oracle Cloud endpoints:
            BUCKET.NAMESPACE.compat.objectstorage.REGION.oraclecloud.com

EXAMPLES
    Upload using configured provider:
        {program_name} cp archive.tar my-bucket:/archives/archive.tar

    Download using configured provider:
        {program_name} cp my-bucket:/archives/archive.tar ./downloaded.tar

    List all objects:
        {program_name} ls my-bucket:

    List objects in folder:
        {program_name} ls my-bucket:/archives/

    Mirror folder to bucket:
        {program_name} mirror ./data/ my-bucket:/data/

    Remove object:
        {program_name} rm my-bucket:/archives/old-file.tar

    Add new provider:
        {program_name} add-provider

EXIT STATUS
    0   Success
    1   Error (missing arguments, authentication failure, transfer failure)""")

class ProgressTracker:
    def __init__(self, total_size, operation="Processing"):
        self.total_size = total_size
        self.processed_bytes = 0
        self.operation = operation
        self.last_print = 0
        self.start_time = time.time()

    def update(self, bytes_processed):
        self.processed_bytes += bytes_processed
        self._print_progress()

    def _print_progress(self):
        if self.total_size > 0:
            percent = self.processed_bytes / self.total_size * 100
        else:
            percent = 0
        processed_mb = self.processed_bytes / (1024 * 1024)
        total_mb = self.total_size / (1024 * 1024)

        now = time.time()
        elapsed = now - self.start_time
        if elapsed > 0 and self.processed_bytes > 0:
            speed_bps = self.processed_bytes / elapsed
            speed_mbps = speed_bps / (1024 * 1024)
            speed_str = f" @ {speed_mbps:.1f} MB/s"
        else:
            speed_str = ""

        if now - self.last_print > 0.1 or \
                self.processed_bytes == self.total_size:
            print(f"\r{self.operation}... {percent:.1f}% " +
                f"({processed_mb:.2f}/{total_mb:.2f} MB){speed_str}",
                end="", flush=True)
            self.last_print = now

class ProgressFileReader:
    def __init__(self, file_path, chunk_size=8192):
        self.file = open(file_path, "rb")
        self.file_path = file_path
        self.total_size = os.path.getsize(file_path)
        self.tracker = ProgressTracker(self.total_size,
            f"Uploading {os.path.basename(file_path)}")
        self.chunk_size = chunk_size

    def read(self, size=-1):
        data = self.file.read(size if size > 0 else self.chunk_size)
        if data:
            self.tracker.update(len(data))
        return data

    def __len__(self):
        return self.total_size

    def close(self):
        self.file.close()

def get_utc_now():
    try:
        return datetime.datetime.now(datetime.UTC)
    except AttributeError:
        return datetime.datetime.utcnow()

def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.expanduser("~/.config/s3c.conf")
    else:
        config_path = os.path.expanduser(config_path)

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config file {config_path}: {e}",
                file=sys.stderr)

    return {"providers": {}}

def save_config(config, config_path=None):
    if config_path is None:
        config_path = os.path.expanduser("~/.config/s3c.conf")
    else:
        config_path = os.path.expanduser(config_path)

    config_dir = os.path.dirname(config_path)
    os.makedirs(config_dir, exist_ok=True)

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

def get_provider_config(name, config):
    for provider_name, provider_config in config.get("providers", {}).items():
        if provider_name == name:
            return provider_config
    return None

def get_credentials_from_env(bucket):
    return {
        "bucket": bucket,
        "access_key": os.environ.get("S3_ACCESS_KEY_ID",
            os.environ.get("AWS_ACCESS_KEY_ID")),
        "secret_access_key": os.environ.get("S3_SECRET_ACCESS_KEY",
            os.environ.get("AWS_SECRET_ACCESS_KEY")),
        "region": os.environ.get("S3_REGION",
            os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
        "storage_class": os.environ.get("S3_STORAGE_CLASS",
            os.environ.get("AWS_S3_STORAGE_CLASS")),
        "domain": os.environ.get("S3_BASE_DOMAIN",
            os.environ.get("AWS_S3_BASE_DOMAIN")),
        "cloudflare_account_id": os.environ.get("S3_CLOUDFLARE_ACCOUNT_ID"),
        "oracle_cloud_namespace": os.environ.get("S3_ORACLE_CLOUD_NAMESPACE"),
    }

def add_provider_interactive(config_path=None):
    config = load_config(config_path)

    print("Add new S3 provider configuration")
    print("=" * 35)

    name = input("Name: ").strip()
    if not name:
        print("Error: Name cannot be empty", file=sys.stderr)
        return False

    if name in config["providers"]:
        overwrite = input(f"Provider '{name}' already exists. " +
            "Overwrite? (y/N): ").strip().lower()
        if overwrite != "y":
            print("Cancelled")
            return False

    bucket = input("Bucket: ").strip()
    access_key = input("Access Key: ").strip()
    secret_key = getpass.getpass("Secret Access Key: ").strip()

    if not all([bucket, access_key, secret_key]):
        print("Error: Bucket, Access Key, and Secret Access Key are required",
            file=sys.stderr)
        return False

    provider_config = {
        "bucket": bucket,
        "access_key": access_key,
        "secret_access_key": secret_key,
    }

    region = input("Region (default: us-east-1): ").strip()
    if region:
        provider_config["region"] = region

    storage_class = input("Storage Class (optional): ").strip()
    if storage_class:
        provider_config["storage_class"] = storage_class

    cloudflare_id = input("Cloudflare Account ID (optional): ").strip()
    if cloudflare_id:
        provider_config["cloudflare_account_id"] = cloudflare_id

    oracle_namespace = input("Oracle Cloud Namespace (optional): ").strip()
    if oracle_namespace:
        provider_config["oracle_cloud_namespace"] = oracle_namespace

    base_domain = input("Base Domain (optional): ").strip()
    if base_domain:
        provider_config["domain"] = base_domain

    config["providers"][name] = provider_config

    try:
        save_config(config, config_path)
        print(f"\nProvider '{name}' added successfully!")
        return True
    except Exception as e:
        print(f"Error saving configuration: {e}", file=sys.stderr)
        return False

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region, service):
    k_date = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    return k_signing

def sha256_hexdigest_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def get_host_and_uri(config, s3_key=""):
    region = config.get("region", "us-east-1")

    if config.get("domain"):
        host = config["domain"]
    elif config.get("cloudflare_account_id"):
        host = f"{config['cloudflare_account_id']}.r2.cloudflarestorage.com"
    elif config.get("oracle_cloud_namespace"):
        if region == "us-east-1":
            region = "us-ashburn-1"
        host = (f"{config['oracle_cloud_namespace']}.compat.objectstorage"
            f".{region}.oraclecloud.com")
    else:
        host = f"s3.{region}.amazonaws.com"

    if s3_key:
        uri = f"/{config['bucket']}/{s3_key}"
    else:
        uri = f"/{config['bucket']}/"
    return host, uri

def create_auth_headers(method, host, uri, config, content_type=None,
        content_length=None, payload_hash=None, query_params=None):
    access_key = config["access_key"]
    secret_key = config["secret_access_key"]
    region = config.get("region", "us-east-1")
    storage_class = config.get("storage_class")
    payload_hash = payload_hash or "UNSIGNED-PAYLOAD"

    now = get_utc_now()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    headers_dict = {
        "host": host,
        "x-amz-date": amz_date,
    }

    if content_type:
        headers_dict["content-type"] = content_type
    if content_length is not None:
        headers_dict["content-length"] = str(content_length)
    if payload_hash:
        headers_dict["x-amz-content-sha256"] = payload_hash
    if storage_class:
        headers_dict["x-amz-storage-class"] = storage_class

    sorted_header_items = sorted((k.lower(), v.strip())
        for k, v in headers_dict.items())

    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted_header_items)
    signed_headers = ";".join(k for k, _ in sorted_header_items)

    canonical_query = ""
    if query_params:
        encoded_params = []
        for k, v in sorted(query_params.items()):
            encoded_k = urllib.parse.quote(str(k), safe="")
            encoded_v = urllib.parse.quote(str(v), safe="")
            encoded_params.append(f"{encoded_k}={encoded_v}")
        canonical_query = "&".join(encoded_params)

    canonical_request = (
        f"{method}\n"
        f"{uri}\n"
        f"{canonical_query}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    signing_key = get_signature_key(secret_key, date_stamp, region, "s3")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"),
        hashlib.sha256).hexdigest()

    authorization_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers_dict["authorization"] = authorization_header

    return headers_dict

def upload_file(config, source_file_path, s3_key):
    if not os.path.isfile(source_file_path):
        print(f"Error: Source file '{source_file_path}' not found",
            file=sys.stderr)
        return False

    host, uri = get_host_and_uri(config, s3_key)

    ext = os.path.splitext(source_file_path)[1].lower()
    content_type = content_types.get(ext, "application/octet-stream")
    content_length = os.path.getsize(source_file_path)
    payload_hash = sha256_hexdigest_file(source_file_path)

    headers = create_auth_headers("PUT", host, uri, config, content_type,
        content_length, payload_hash)

    print(f"Uploading to: {host}")

    conn = http.client.HTTPSConnection(host)
    reader = ProgressFileReader(source_file_path)

    try:
        conn.request("PUT", uri, body=reader, headers=headers)
        response = conn.getresponse()
        print(f"\nStatus: {response.status} {response.reason}")

        if response.status >= 300:
            body = response.read().decode()
            print(body, file=sys.stderr)
            return False
        else:
            print(f"Upload successful: {config['bucket']}/{s3_key}")
            return True
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        return False
    finally:
        reader.close()
        conn.close()

def download_file(config, s3_key, dest_file_path):
    host, uri = get_host_and_uri(config, s3_key)
    headers = create_auth_headers("GET", host, uri, config)

    print(f"Downloading from: {host}")

    conn = http.client.HTTPSConnection(host)

    try:
        conn.request("GET", uri, headers=headers)
        response = conn.getresponse()

        if response.status != 200:
            body = response.read().decode()
            print(f"Error: {response.status} {response.reason}",
                file=sys.stderr)
            print(body, file=sys.stderr)
            return False

        content_length = int(response.getheader("content-length", 0))
        tracker = ProgressTracker(content_length,
            f"Downloading {os.path.basename(dest_file_path)}")

        os.makedirs(os.path.dirname(os.path.abspath(dest_file_path)),
            exist_ok=True)

        with open(dest_file_path, "wb") as f:
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                f.write(chunk)
                tracker.update(len(chunk))

        print(f"\nDownload successful: {dest_file_path}")
        return True

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        return False
    finally:
        conn.close()

def list_objects(config, prefix=""):
    host, uri = get_host_and_uri(config)

    query_params = {"delimiter": "/"}
    if prefix:
        query_params["prefix"] = prefix

    headers = create_auth_headers("GET", host, uri, config,
        query_params=query_params)

    conn = http.client.HTTPSConnection(host)

    try:
        query_string = ""
        if query_params:
            query_string = "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}"
                for k, v in query_params.items())

        conn.request("GET", uri + query_string, headers=headers)
        response = conn.getresponse()

        if response.status != 200:
            body = response.read().decode()
            print(f"Error: {response.status} {response.reason}",
                file=sys.stderr)
            print(body, file=sys.stderr)
            return False

        body = response.read().decode()

        try:
            root = xml.etree.ElementTree.fromstring(body)

            ns = ""
            if root.tag.startswith("{"):
                ns = "{" + root.tag.split("}")[0][1:] + "}"

            items = []

            for prefix_elem in root.findall(f"{ns}CommonPrefixes"):
                prefix_key = prefix_elem.find(f"{ns}Prefix")
                if prefix_key is not None:
                    dir_name = prefix_key.text
                    items.append({
                        "key": dir_name,
                        "size": None,
                        "modified": "",
                        "is_dir": True
                    })

            for content in root.findall(f"{ns}Contents"):
                key_elem = content.find(f"{ns}Key")
                size_elem = content.find(f"{ns}Size")
                modified_elem = content.find(f"{ns}LastModified")

                if key_elem is not None:
                    key = key_elem.text
                    size = int(size_elem.text) if size_elem is not None else 0
                    modified = modified_elem.text if modified_elem \
                        is not None else ""

                    items.append({
                        "key": key,
                        "size": size,
                        "modified": modified,
                        "is_dir": False
                    })

            if not items:
                print("No objects found")
                return True

            items.sort(key=lambda x: (not x["is_dir"], x["key"]))

            for item in items:
                if item["is_dir"]:
                    dir_name = item["key"].rstrip("/") + "/"
                    print(f"{'-':19} {'-':>8} {dir_name}")
                else:
                    size = item["size"]
                    if size < 1024:
                        size_str = f"{size}B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f}K"
                    elif size < 1024 * 1024 * 1024:
                        size_str = f"{size / (1024 * 1024):.1f}M"
                    elif size < 1024 * 1024 * 1024 * 1024:
                        size_str = f"{size / (1024 * 1024 * 1024):.1f}G"
                    else:
                        size_str = f"{size / (1024 * 1024 * 1024 * 1024):.1f}T"

                    if item["modified"]:
                        try:
                            dt = datetime.datetime.fromisoformat(
                                item["modified"].replace("Z", "+00:00"))
                            modified_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            modified_str = item["modified"][:19]
                        print(f"{modified_str:19} " +
                            f"{size_str:>8} {item['key']}")
                    else:
                        print(f"{'-':19} {size_str:>8} {item['key']}")

            return True

        except xml.etree.ElementTree.ParseError as e:
            print(f"Error parsing XML response: {e}", file=sys.stderr)
            print(body, file=sys.stderr)
            return False

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False
    finally:
        conn.close()

def list_objects_recursive(config, prefix=""):
    host, uri = get_host_and_uri(config)
    all_objects = []
    continuation_token = None

    while True:
        query_params = {}
        if prefix:
            query_params["prefix"] = prefix
        if continuation_token:
            query_params["continuation-token"] = continuation_token

        headers = create_auth_headers("GET", host, uri, config,
            query_params=query_params)

        conn = http.client.HTTPSConnection(host)

        try:
            query_string = ""
            if query_params:
                query_string = "?" + "&".join(
                    f"{k}={urllib.parse.quote(str(v))}"
                    for k, v in query_params.items()
                )

            conn.request("GET", uri + query_string, headers=headers)
            response = conn.getresponse()

            if response.status != 200:
                body = response.read().decode()
                print(f"Error: {response.status} {response.reason}",
                    file=sys.stderr)
                print(body, file=sys.stderr)
                return None

            body = response.read().decode()

            try:
                root = xml.etree.ElementTree.fromstring(body)

                ns = ""
                if root.tag.startswith("{"):
                    ns = "{" + root.tag.split("}")[0][1:] + "}"

                for content in root.findall(f"{ns}Contents"):
                    key_elem = content.find(f"{ns}Key")
                    size_elem = content.find(f"{ns}Size")
                    modified_elem = content.find(f"{ns}LastModified")

                    if key_elem is not None:
                        key = key_elem.text
                        size = int(size_elem.text) if \
                            size_elem is not None else 0
                        modified = modified_elem.text if \
                            modified_elem is not None else ""

                        all_objects.append({
                            "key": key,
                            "size": size,
                            "modified": modified
                        })

                is_truncated = root.find(f"{ns}IsTruncated")
                if is_truncated is not None and is_truncated.text == "true":
                    next_token = root.find(f"{ns}NextContinuationToken")
                    if next_token is not None:
                        continuation_token = next_token.text
                    else:
                        break
                else:
                    break

            except xml.etree.ElementTree.ParseError as e:
                print(f"Error parsing XML response: {e}", file=sys.stderr)
                print(body, file=sys.stderr)
                return None

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return None
        finally:
            conn.close()

    return all_objects

def remove_object(config, s3_key):
    host, uri = get_host_and_uri(config, s3_key)
    headers = create_auth_headers("DELETE", host, uri, config)

    print(f"Removing from: {host}")

    conn = http.client.HTTPSConnection(host)

    try:
        conn.request("DELETE", uri, headers=headers)
        response = conn.getresponse()

        if response.status == 204 or response.status == 200:
            print(f"Remove successful: {config['bucket']}/{s3_key}")
            return True
        else:
            body = response.read().decode()
            print(f"Error: {response.status} {response.reason}",
                file=sys.stderr)
            print(body, file=sys.stderr)
            return False

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False
    finally:
        conn.close()

def mirror_directory(config, local_path, s3_prefix,
        remove_extra=False, overwrite=False):
    if not os.path.isdir(local_path):
        print(f"Error: Local path '{local_path}' is not a directory",
            file=sys.stderr)
        return False

    print(f"Scanning local directory: {local_path}")

    local_files = {}
    for root, _, files in os.walk(local_path):
        for filename in files:
            local_file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(local_file_path, local_path)
            rel_path = rel_path.replace(os.sep, "/")

            mtime = os.path.getmtime(local_file_path)
            size = os.path.getsize(local_file_path)

            local_files[rel_path] = {
                "path": local_file_path,
                "mtime": mtime,
                "size": size
            }

    print(f"Found {len(local_files)} local files")
    print(f"Listing remote objects with prefix: {s3_prefix}")

    remote_objects = list_objects_recursive(config, s3_prefix)
    if remote_objects is None:
        print("Error: Failed to list remote objects", file=sys.stderr)
        return False

    remote_files = {}
    for obj in remote_objects:
        key = obj["key"]
        if s3_prefix and key.startswith(s3_prefix):
            rel_key = key[len(s3_prefix):]
            if rel_key.startswith("/"):
                rel_key = rel_key[1:]
        else:
            rel_key = key

        if rel_key:
            try:
                s3_mtime_str = obj["modified"]
                s3_dt = datetime.datetime.fromisoformat(
                    s3_mtime_str.replace("Z", "+00:00"))
                s3_mtime = s3_dt.timestamp()

                remote_files[rel_key] = {
                    "key": key,
                    "mtime": s3_mtime,
                    "size": obj["size"]
                }
            except:
                remote_files[rel_key] = {
                    "key": key,
                    "mtime": 0,
                    "size": obj["size"]
                }

    print(f"Found {len(remote_files)} remote files")

    files_to_upload = []
    files_to_skip = []

    for rel_path, local_info in local_files.items():
        if rel_path in remote_files:
            remote_info = remote_files[rel_path]

            if overwrite:
                files_to_upload.append(rel_path)
            else:
                time_diff = local_info["mtime"] - remote_info["mtime"]
                if time_diff > -10:
                    files_to_upload.append(rel_path)
                else:
                    files_to_skip.append(rel_path)
        else:
            files_to_upload.append(rel_path)

    files_to_remove = []
    if remove_extra:
        for rel_key in remote_files:
            if rel_key not in local_files:
                files_to_remove.append(rel_key)

    print(f"\nSync summary:")
    print(f"  Files to upload: {len(files_to_upload)}")
    print(f"  Files to skip (up-to-date): {len(files_to_skip)}")
    if remove_extra:
        print(f"  Files to remove: {len(files_to_remove)}")
    print()

    upload_success = 0
    upload_failed = 0

    for i, rel_path in enumerate(files_to_upload, 1):
        local_file_path = local_files[rel_path]["path"]
        s3_key = s3_prefix
        if s3_key and not s3_key.endswith("/"):
            s3_key += "/"
        s3_key += rel_path

        print(f"[{i}/{len(files_to_upload)}] Uploading: {rel_path}")

        if upload_file(config, local_file_path, s3_key):
            upload_success += 1
        else:
            upload_failed += 1
            print(f"Failed to upload: {rel_path}", file=sys.stderr)

    remove_success = 0
    remove_failed = 0

    if remove_extra and files_to_remove:
        print()
        for i, rel_key in enumerate(files_to_remove, 1):
            s3_key = remote_files[rel_key]["key"]
            print(f"[{i}/{len(files_to_remove)}] Removing: {rel_key}")

            if remove_object(config, s3_key):
                remove_success += 1
            else:
                remove_failed += 1
                print(f"Failed to remove: {rel_key}", file=sys.stderr)

    print(f"\nMirror complete:")
    print(f"  Uploaded: {upload_success}/{len(files_to_upload)}")
    if upload_failed > 0:
        print(f"  Upload failed: {upload_failed}")
    if remove_extra:
        print(f"  Removed: {remove_success}/{len(files_to_remove)}")
        if remove_failed > 0:
            print(f"  Remove failed: {remove_failed}")

    return upload_failed == 0 and remove_failed == 0

def parse_s3_path(path):
    if ":" not in path:
        return None, None

    provider, s3_path = path.split(":", 1)
    s3_key = s3_path.lstrip("/") if s3_path else ""
    return provider, s3_key

def main():
    program_name = os.path.basename(sys.argv[0])

    config_path = None
    args = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--help", "-h"):
            print_help()
            sys.exit(0)
        elif arg in ("--config", "-c"):
            if i + 1 >= len(sys.argv):
                print(f"Error: {arg} requires a path argument",
                    file=sys.stderr)
                sys.exit(1)
            config_path = sys.argv[i + 1]
            i += 2
        else:
            args.append(arg)
            i += 1

    if len(args) == 0:
        print(f"Usage: {program_name} [OPTIONS] cp SOURCE DESTINATION",
            file=sys.stderr)
        print(f"   or: {program_name} [OPTIONS] ls PROVIDER:[PATH]",
            file=sys.stderr)
        print(f"   or: {program_name} [OPTIONS] rm PROVIDER:/PATH",
            file=sys.stderr)
        print(f"   or: {program_name} [OPTIONS] mirror [--remove] " +
            "[--overwrite] LOCAL_DIR PROVIDER:/PATH", file=sys.stderr)
        print(f"   or: {program_name} [OPTIONS] add-provider",
            file=sys.stderr)
        print(f"Try '{program_name} --help' for more information",
            file=sys.stderr)
        sys.exit(1)

    command = args[0]

    if command == "add-provider":
        success = add_provider_interactive(config_path)
        sys.exit(0 if success else 1)

    elif command == "cp":
        if len(args) != 3:
            print(f"Usage: {program_name} cp SOURCE DESTINATION",
                file=sys.stderr)
            sys.exit(1)

        source = args[1]
        destination = args[2]

        config = load_config(config_path)

        src_provider, source_key = parse_s3_path(source)
        dest_provider, dest_key = parse_s3_path(destination)

        if src_provider and not dest_provider:
            provider_config = get_provider_config(src_provider, config)
            if not provider_config:
                provider_config = get_credentials_from_env(src_provider)
                if (not provider_config["access_key"] or
                        not provider_config["secret_access_key"]):
                    print(f"Error: No configuration found for provider " +
                        f"'{src_provider}' and no environment variables set",
                        file=sys.stderr)
                    sys.exit(1)

            success = download_file(provider_config, source_key, destination)

        elif not src_provider and dest_provider:
            provider_config = get_provider_config(dest_provider, config)
            if not provider_config:
                provider_config = get_credentials_from_env(dest_provider)
                if (not provider_config["access_key"] or
                    not provider_config["secret_access_key"]):
                    print(f"Error: No configuration found for provider " +
                        f"'{dest_provider}' and no environment variables set",
                        file=sys.stderr)
                    sys.exit(1)

            success = upload_file(provider_config, source, dest_key)

        else:
            print("Error: One path must be local and the other must be " +
                "in provider:/path format", file=sys.stderr)
            sys.exit(1)

        sys.exit(0 if success else 1)

    elif command == "ls":
        if len(args) != 2:
            print(f"Usage: {program_name} ls PROVIDER:[PATH]",
                file=sys.stderr)
            sys.exit(1)

        path = args[1]
        provider, prefix = parse_s3_path(path)

        if not provider:
            print("Error: Path must be in provider:[path] format",
                file=sys.stderr)
            sys.exit(1)

        config = load_config(config_path)
        provider_config = get_provider_config(provider, config)

        if not provider_config:
            provider_config = get_credentials_from_env(provider)
            if (not provider_config["access_key"] or
                not provider_config["secret_access_key"]):
                print(f"Error: No configuration found for provider " +
                    f"'{provider}' and no environment variables set",
                    file=sys.stderr)
                sys.exit(1)

        success = list_objects(provider_config, prefix)
        sys.exit(0 if success else 1)

    elif command == "rm":
        if len(args) != 2:
            print(f"Usage: {program_name} rm PROVIDER:/PATH",
                file=sys.stderr)
            sys.exit(1)

        path = args[1]
        provider, s3_key = parse_s3_path(path)

        if not provider or not s3_key:
            print("Error: Path must be in provider:/path format",
                file=sys.stderr)
            sys.exit(1)

        config = load_config(config_path)
        provider_config = get_provider_config(provider, config)

        if not provider_config:
            provider_config = get_credentials_from_env(provider)
            if (not provider_config["access_key"] or
                not provider_config["secret_access_key"]):
                print(f"Error: No configuration found for provider " +
                    f"'{provider}' and no environment variables set",
                    file=sys.stderr)
                sys.exit(1)

        success = remove_object(provider_config, s3_key)
        sys.exit(0 if success else 1)

    elif command == "mirror":
        remove_extra = False
        overwrite_all = False
        mirror_args = args[1:]

        while mirror_args and mirror_args[0].startswith("--"):
            if mirror_args[0] == "--remove":
                remove_extra = True
                mirror_args = mirror_args[1:]
            elif mirror_args[0] == "--overwrite":
                overwrite_all = True
                mirror_args = mirror_args[1:]
            else:
                print(f"Error: Unknown option '{mirror_args[0]}'",
                    file=sys.stderr)
                sys.exit(1)

        if len(mirror_args) != 2:
            print(f"Usage: {program_name} mirror [--remove] [--overwrite] " +
                "LOCAL_DIR PROVIDER:/PATH", file=sys.stderr)
            sys.exit(1)

        local_path = mirror_args[0]
        remote_path = mirror_args[1]

        provider, s3_prefix = parse_s3_path(remote_path)

        if not provider:
            print("Error: Remote path must be in provider:/path format",
                file=sys.stderr)
            sys.exit(1)

        config = load_config(config_path)
        provider_config = get_provider_config(provider, config)

        if not provider_config:
            provider_config = get_credentials_from_env(provider)
            if (not provider_config["access_key"] or
                    not provider_config["secret_access_key"]):
                print(f"Error: No configuration found for provider " +
                    f"'{provider}' and no environment variables set",
                    file=sys.stderr)
                sys.exit(1)

        success = mirror_directory(provider_config, local_path, s3_prefix,
            remove_extra, overwrite_all)
        sys.exit(0 if success else 1)

    else:
        print(f"Error: Unknown command '{command}'", file=sys.stderr)
        print(f"Try '{program_name} --help' for more information",
            file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

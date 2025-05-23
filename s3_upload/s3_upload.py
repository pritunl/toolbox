#!/usr/bin/env python3
import sys
import os
import datetime
import hashlib
import hmac
import http.client
import time

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
    print(f"""{program_name} - upload files to S3-compatible storage

Usage: {program_name} [OPTIONS] SOURCE_FILE BUCKET/PATH
  or   {program_name} --help

DESCRIPTION
    Dependency-free tool for uploading files to S3-compatible storage services.
    Implements AWS Signature Version 4 authentication.

ARGUMENTS
    SOURCE_FILE
        Path to the local file to upload

    BUCKET/PATH
        Destination in the format bucket_name/object_key
        Example: backup-bucket/archives/archive.tar

OPTIONS
    --help, -h
        Display this help message and exit

ENVIRONMENT VARIABLES
    Authentication (Required):
        S3_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID
            Access key ID for authentication.

        S3_SECRET_ACCESS_KEY, AWS_SECRET_ACCESS_KEY
            Secret access key for authentication.

    Configuration (Optional):
        S3_REGION, AWS_DEFAULT_REGION
            AWS region for the S3 service (default: us-east-1)

        S3_STORAGE_CLASS, AWS_S3_STORAGE_CLASS
            Storage class for uploaded objects (e.g., STANDARD,STANDARD_IA,
            GLACIER, DEEP_ARCHIVE)

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
    Basic AWS S3 upload:
        export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        {program_name} archive.tar backup-bucket/archives/archive.tar

    Upload with storage class:
        export S3_STORAGE_CLASS="GLACIER"
        {program_name} archive.tar backup-bucket/archives/archive.tar

    Cloudflare R2 upload:
        export S3_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        export S3_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        export S3_CLOUDFLARE_ACCOUNT_ID="a8f2b4e6d9c1f7a3b5e8d2c9f4a7b1e6"
        {program_name} archive.tar r2-backup-bucket/archives/archive.tar

    Oracle Cloud Object Storage:
        export S3_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        export S3_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        export S3_ORACLE_CLOUD_NAMESPACE="tenancy9423"
        export S3_REGION="us-ashburn-1"
        {program_name} archive.tar oci-backup-bucket/archives/archive.tar

    Custom S3-compatible service:
        export S3_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        export S3_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        export S3_DOMAIN="s3.example.com"
        {program_name} archive.tar s3-backup-bucket/archives/archive.tar

SUPPORTED FILE TYPES
    The tool automatically detects MIME types for file extensions:
    - Web files: .html, .css, .js, .json, .xml
    - Images: .jpg, .png, .gif, .svg, .webp, .ico
    - Documents: .pdf, .txt, .md, .csv
    - Archives: .zip, .gz, .tar, .rar, .7z
    - Executables: .exe, .dll, .so, .apk, .deb, .rpm
    - Fonts: .ttf, .otf, .woff, .woff2
    - Code: .py, .go, .sh

EXIT STATUS
    0   Success
    1   Error (missing arguments, authentication failure, upload failure)""")

class ProgressFileReader:
    def __init__(self, file_path, chunk_size=8192):
        self.file = open(file_path, "rb")
        self.file_path = file_path
        self.total_size = os.path.getsize(file_path)
        self.read_bytes = 0
        self.chunk_size = chunk_size
        self.last_print = 0

    def read(self, size=-1):
        data = self.file.read(size if size > 0 else self.chunk_size)
        if data:
            self.read_bytes += len(data)
            self._print_progress()
        return data

    def _print_progress(self):
        percent = self.read_bytes / self.total_size * 100
        read_mb = self.read_bytes / (1024 * 1024)
        total_mb = self.total_size / (1024 * 1024)
        now = time.time()
        if now - self.last_print > 0.1 or self.read_bytes == self.total_size:
            print(f"\rUploading {self.file_path}... {percent:.1f}% " +
                f"({read_mb:.2f}/{total_mb:.2f} MB)", end="", flush=True)
            self.last_print = now

    def __len__(self):
        return self.total_size

    def close(self):
        self.file.close()

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

def main():
    program_name = os.path.basename(sys.argv[0])

    if len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h"):
        print_help()
        sys.exit(0)

    if len(sys.argv) != 3:
        print(f"Usage: {program_name} <source_file> <bucket/path>",
            file=sys.stderr)
        print(f"Try '{program_name} --help' for more information",
            file=sys.stderr)
        sys.exit(1)

    source_file_path = sys.argv[1]
    dest_path = sys.argv[2]

    if not os.path.isfile(source_file_path):
        print(f"Error: Source file '{source_file_path}' not found",
            file=sys.stderr)
        sys.exit(1)

    access_key = os.environ.get("S3_ACCESS_KEY_ID",
        os.environ.get("AWS_ACCESS_KEY_ID"))
    secret_key = os.environ.get("S3_SECRET_ACCESS_KEY",
        os.environ.get("AWS_SECRET_ACCESS_KEY"))
    region = os.environ.get("S3_REGION",
        os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    storage_class = os.environ.get("S3_STORAGE_CLASS",
        os.environ.get("AWS_S3_STORAGE_CLASS"))
    base_domain = os.environ.get("S3_DOMAIN",
        os.environ.get("AWS_S3_DOMAIN"))
    cloudflare_account_id = os.environ.get("S3_CLOUDFLARE_ACCOUNT_ID")
    oracle_cloud_namespace = os.environ.get("S3_ORACLE_CLOUD_NAMESPACE")

    if not access_key or not secret_key:
        print("Error: Missing required environment variables",
            file=sys.stderr)
        print(f"Try '{program_name} --help' for more information",
            file=sys.stderr)
        sys.exit(1)

    if "/" not in dest_path:
        print("Error: Destination path must include bucket and " +
            "object key (e.g. bucket/archive.tar)", file=sys.stderr)
        sys.exit(1)

    bucket, s3_key = dest_path.split("/", 1)

    if base_domain:
        host = base_domain
    elif cloudflare_account_id:
        host = f"{cloudflare_account_id}.r2.cloudflarestorage.com"
    elif oracle_cloud_namespace:
        if region == "us-east-1":
            region = "us-ashburn-1"
        host = (f"{oracle_cloud_namespace}.compat.objectstorage"
            f".{region}.oraclecloud.com")
    else:
        host = f"s3.{region}.amazonaws.com"

    uri = f"/{bucket}/{s3_key}"
    method = "PUT"

    ext = os.path.splitext(source_file_path)[1].lower()
    content_type = content_types.get(ext, "application/octet-stream")

    content_length = str(os.path.getsize(source_file_path))
    payload_hash = sha256_hexdigest_file(source_file_path)

    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_headers = (
        f"content-length:{content_length}\n"
        f"content-type:{content_type}\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-length;content-type;host;" + \
        "x-amz-content-sha256;x-amz-date"
    if storage_class:
        canonical_headers += f"x-amz-storage-class:{storage_class}\n"
        signed_headers += ";x-amz-storage-class"

    canonical_request = (
        f"{method}\n"
        f"{uri}\n"
        f"\n"
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

    headers = {
        "host": host,
        "content-type": content_type,
        "content-length": content_length,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "authorization": authorization_header
    }

    if storage_class:
        headers["x-amz-storage-class"] = storage_class

    print(f"Uploading to: {host}")

    conn = http.client.HTTPSConnection(host)
    reader = ProgressFileReader(source_file_path)

    try:
        conn.request(method, uri, body=reader, headers=headers)
        response = conn.getresponse()
        print(f"\nStatus: {response.status} {response.reason}")
        body = response.read().decode()
        if response.status >= 300:
            print(body, file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Upload successful {dest_path}")
    finally:
        reader.close()

if __name__ == "__main__":
    main()

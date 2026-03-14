#!/usr/bin/env python3
"""
Nooshdaroo OTA Config Publisher

Encrypts a config JSON with ChaCha20-Poly1305, chunks it into DNS TXT records,
and publishes to Route53. Clients fetch and decrypt with --ota-domain and --ota-nonce.

Wire format per TXT record:
  v=1 id=<timestamp> chunks=<N> chunk=<i> [key=<b64>] d=<b64_data>
  (key only appears in chunk 1)

Prerequisites:
  pip3 install cryptography boto3

Usage:
  # Publish config to DNS TXT records:
  python3 tools/publish-ota.py config.json \
    --zone-id Z09197321VANTA6VREKAZ \
    --domain _cfg.example.com \
    --nonce "my-12char-ab"

  # Dry run (show what would be published):
  python3 tools/publish-ota.py config.json \
    --zone-id Z09197321VANTA6VREKAZ \
    --domain _cfg.example.com \
    --nonce "my-12char-ab" \
    --dry-run

  # Verify published records:
  python3 tools/publish-ota.py --verify --domain _cfg.example.com --nonce "my-12char-ab"

  # Decrypt and dump existing OTA config from DNS:
  python3 tools/publish-ota.py --fetch --domain _cfg.example.com --nonce "my-12char-ab"
"""

import os
import sys
import json
import time
import base64
import argparse
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("ota")

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("ERROR: pip3 install cryptography")
    sys.exit(1)

# Max base64 data per TXT record chunk (~240 bytes keeps us under DNS limits)
MAX_CHUNK_DATA_B64 = 240


def encrypt_config(config_json: str, nonce: bytes) -> tuple:
    """Encrypt config JSON with ChaCha20-Poly1305. Returns (key, ciphertext)."""
    key = os.urandom(32)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, config_json.encode(), None)
    return key, ciphertext


def decrypt_config(key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    """Decrypt config ciphertext. Returns JSON string."""
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def chunk_ciphertext(key: bytes, ciphertext: bytes) -> list:
    """Split encrypted config into DNS TXT record values."""
    data_b64 = base64.b64encode(ciphertext).decode()
    key_b64 = base64.b64encode(key).decode()
    config_id = time.strftime("%Y%m%d-%H%M%S")

    chunks = []
    offset = 0
    while offset < len(data_b64):
        chunks.append(data_b64[offset : offset + MAX_CHUNK_DATA_B64])
        offset += MAX_CHUNK_DATA_B64

    total = len(chunks)
    records = []
    for i, chunk_data in enumerate(chunks, 1):
        parts = [
            "v=1",
            f"id={config_id}",
            f"chunks={total}",
            f"chunk={i}",
        ]
        if i == 1:
            parts.append(f"key={key_b64}")
        parts.append(f"d={chunk_data}")
        records.append(" ".join(parts))

    return records


def upsert_route53(zone_id: str, domain: str, records: list, dry_run: bool = False):
    """Upsert TXT records to AWS Route53."""
    resource_records = [{"Value": f'"{rec}"'} for rec in records]

    change = {
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": domain,
                    "Type": "TXT",
                    "TTL": 60,
                    "ResourceRecords": resource_records,
                },
            }
        ],
    }

    if dry_run:
        log.info("[DRY-RUN] Would upsert %d TXT records to %s", len(records), domain)
        for i, rec in enumerate(records, 1):
            log.info("  TXT[%d/%d]: %s... (%d chars)", i, len(records), rec[:80], len(rec))
        return True

    try:
        import boto3

        client = boto3.client("route53")
        resp = client.change_resource_record_sets(
            HostedZoneId=zone_id, ChangeBatch=change
        )
        change_id = resp["ChangeInfo"]["Id"]
        log.info("Route53 upsert OK: %s (%d records to %s)", change_id, len(records), domain)
        return True
    except ImportError:
        log.error("boto3 not installed. pip3 install boto3")
        return False
    except Exception as e:
        log.error("Route53 upsert failed: %s", e)
        return False


def fetch_txt_records(domain: str) -> list:
    """Fetch TXT records for a domain using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", domain, "@8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = []
        for line in result.stdout.strip().split("\n"):
            # Remove surrounding quotes
            line = line.strip().strip('"')
            if line.startswith("v=1"):
                lines.append(line)
        return sorted(lines, key=lambda x: int(x.split("chunk=")[1].split()[0]) if "chunk=" in x else 0)
    except Exception as e:
        log.error("dig failed: %s", e)
        return []


def parse_txt_records(records: list) -> tuple:
    """Parse TXT records back into (key, ciphertext). Returns (key_bytes, ciphertext_bytes)."""
    key_b64 = None
    data_chunks = {}
    total_chunks = 0

    for rec in records:
        parts = {}
        for token in rec.split():
            if "=" in token:
                k, v = token.split("=", 1)
                parts[k] = v

        chunk_num = int(parts.get("chunk", 0))
        total_chunks = max(total_chunks, int(parts.get("chunks", 0)))

        if "key" in parts:
            key_b64 = parts["key"]
        if "d" in parts:
            data_chunks[chunk_num] = parts["d"]

    if not key_b64:
        raise ValueError("No key found in TXT records")

    # Reassemble data in order
    data_b64 = ""
    for i in range(1, total_chunks + 1):
        if i not in data_chunks:
            raise ValueError(f"Missing chunk {i}/{total_chunks}")
        data_b64 += data_chunks[i]

    return base64.b64decode(key_b64), base64.b64decode(data_b64)


def cmd_publish(args):
    """Encrypt and publish config to Route53."""
    with open(args.config_file) as f:
        config_json = f.read().strip()

    # Validate JSON
    config = json.loads(config_json)
    log.info("Config: %d bytes, keys: %s", len(config_json), list(config.keys()))

    # Compact JSON
    compact = json.dumps(config, separators=(",", ":"), sort_keys=True)
    log.info("Compact: %d bytes", len(compact))

    nonce = args.nonce.encode()
    if len(nonce) != 12:
        log.error("Nonce must be exactly 12 bytes (got %d)", len(nonce))
        sys.exit(1)

    key, ciphertext = encrypt_config(compact, nonce)
    records = chunk_ciphertext(key, ciphertext)
    log.info("Encrypted: %d bytes → %d TXT records", len(ciphertext), len(records))

    if not args.zone_id:
        log.error("--zone-id required for publishing")
        sys.exit(1)

    ok = upsert_route53(args.zone_id, args.domain, records, dry_run=args.dry_run)

    if ok and not args.dry_run:
        log.info("\nPublished! Clients fetch with:")
        log.info("  ./nooshdaroo --ota-domain %s --ota-nonce %s --ota-refresh", args.domain, args.nonce)
        log.info("\nVerify with:")
        log.info("  python3 tools/publish-ota.py --verify --domain %s --nonce %s", args.domain, args.nonce)


def cmd_verify(args):
    """Verify DNS TXT records exist and are parseable."""
    log.info("Fetching TXT records for %s...", args.domain)
    records = fetch_txt_records(args.domain)
    if not records:
        log.error("No TXT records found")
        sys.exit(1)

    log.info("Found %d TXT records", len(records))
    for i, rec in enumerate(records, 1):
        log.info("  [%d] %s...(%d chars)", i, rec[:60], len(rec))

    # Try to parse
    try:
        key, ciphertext = parse_txt_records(records)
        log.info("Parsed: key=%d bytes, ciphertext=%d bytes", len(key), len(ciphertext))
    except Exception as e:
        log.error("Parse failed: %s", e)
        sys.exit(1)

    # Try to decrypt
    if args.nonce:
        nonce = args.nonce.encode()
        try:
            plaintext = decrypt_config(key, ciphertext, nonce)
            config = json.loads(plaintext)
            log.info("Decrypted OK! Config keys: %s", list(config.keys()))
            if "transport" in config:
                dnstt = config["transport"].get("dnstt", {})
                domains = dnstt.get("domains", [])
                resolvers = dnstt.get("udp_resolvers", [])
                log.info("  %d domains, %d resolvers", len(domains), len(resolvers))
        except Exception as e:
            log.error("Decryption failed: %s", e)
            sys.exit(1)
    else:
        log.info("(add --nonce to verify decryption)")


def cmd_fetch(args):
    """Fetch, decrypt, and dump OTA config from DNS."""
    nonce = args.nonce.encode()
    if len(nonce) != 12:
        log.error("Nonce must be exactly 12 bytes")
        sys.exit(1)

    records = fetch_txt_records(args.domain)
    if not records:
        log.error("No TXT records found for %s", args.domain)
        sys.exit(1)

    key, ciphertext = parse_txt_records(records)
    plaintext = decrypt_config(key, ciphertext, nonce)
    config = json.loads(plaintext)
    print(json.dumps(config, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Nooshdaroo OTA Config Publisher — encrypt, chunk, publish to DNS TXT"
    )
    parser.add_argument("config_file", nargs="?", help="Path to config.json to publish")
    parser.add_argument("--domain", required=True, help="DNS domain for TXT records (e.g. _cfg.example.com)")
    parser.add_argument("--nonce", help="ChaCha20-Poly1305 nonce (exactly 12 ASCII chars)")
    parser.add_argument("--zone-id", help="AWS Route53 hosted zone ID")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be published")
    parser.add_argument("--verify", action="store_true", help="Verify existing DNS TXT records")
    parser.add_argument("--fetch", action="store_true", help="Fetch and decrypt OTA config from DNS")

    args = parser.parse_args()

    if args.fetch:
        if not args.nonce:
            parser.error("--fetch requires --nonce")
        cmd_fetch(args)
    elif args.verify:
        cmd_verify(args)
    elif args.config_file:
        if not args.nonce:
            parser.error("publishing requires --nonce")
        cmd_publish(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

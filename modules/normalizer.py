"""
Module 2: Normalization Engine
Cleans, validates, deduplicates, and standardizes all IOCs
into a unified structure with metadata.
"""

import re
import ipaddress
from datetime import datetime, timezone

WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "example.com", "localhost", "windowsupdate.com", "ubuntu.com"
}
WHITELIST_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "8.8.4.4"}


def validate_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def validate_domain(v):
    pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(pattern.match(v)) and len(v) <= 253


def validate_url(v):
    return v.startswith(("http://", "https://")) and "." in v and len(v) > 10


def validate_hash(v, htype):
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    expected = lengths.get(htype)
    clean = v.lower()
    return (len(clean) == expected if expected else len(clean) in (32, 40, 64)) \
           and all(c in "0123456789abcdef" for c in clean)


def validate_email(v):
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', v))


VALIDATORS = {
    "ip":     validate_ip,
    "domain": validate_domain,
    "url":    validate_url,
    "email":  validate_email,
    "md5":    lambda v: validate_hash(v, "md5"),
    "sha1":   lambda v: validate_hash(v, "sha1"),
    "sha256": lambda v: validate_hash(v, "sha256"),
    "hash":   lambda v: validate_hash(v, "hash"),
}


def normalize_ioc(raw):
    itype = raw.get("type", "").lower().strip()
    value = raw.get("value", "").strip()

    if not itype or not value:
        return None

    # Normalize casing
    if itype != "url":
        value = value.lower()
    else:
        value = value.rstrip("/")

    # Whitelist checks
    if itype == "ip"     and value in WHITELIST_IPS:
        return None
    if itype == "domain" and value in WHITELIST_DOMAINS:
        return None

    # Validate
    validator = VALIDATORS.get(itype)
    if validator and not validator(value):
        return None

    return {
        "type":           itype,
        "value":          value,
        "source":         raw.get("source", "unknown"),
        "severity":       raw.get("severity", "unknown"),
        "tags":           raw.get("tags", []),
        "first_seen":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "feed_count":     1,
        "sources":        [raw.get("source", "unknown")],
    }


def normalize_all(raw_iocs):
    print(f"\n{'='*60}")
    print("  STEP 2 & 3 -- NORMALIZING & DEDUPLICATING")
    print(f"{'='*60}")

    SEV_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
    seen     = {}
    invalid  = 0
    dupes    = 0

    for raw in raw_iocs:
        norm = normalize_ioc(raw)
        if norm is None:
            invalid += 1
            continue

        key = (norm["type"], norm["value"])
        if key in seen:
            existing = seen[key]
            src = norm["source"]
            if src not in existing["sources"]:
                existing["sources"].append(src)
            if SEV_RANK.get(norm["severity"], 0) > SEV_RANK.get(existing["severity"], 0):
                existing["severity"] = norm["severity"]
            dupes += 1
        else:
            seen[key] = norm

    normalized = list(seen.values())

    print(f"  Raw input:           {len(raw_iocs)}")
    print(f"  Invalid / dropped:   {invalid}")
    print(f"  Duplicates merged:   {dupes}")
    print(f"  Unique IOCs:         {len(normalized)}")

    counts = {}
    for ioc in normalized:
        counts[ioc["type"]] = counts.get(ioc["type"], 0) + 1
    print("\n  Breakdown by type:")
    for t, c in sorted(counts.items()):
        print(f"    {t:<10} -> {c}")

    return normalized

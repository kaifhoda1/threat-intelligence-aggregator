"""
Module 1: IOC Feed Parser
Parses TXT, CSV, JSON feed files and extracts all IOC types.
Supports: IPs, Domains, URLs, MD5/SHA1/SHA256 hashes, Emails
"""

import re
import csv
import json
import os
import ipaddress

# ─── Regex Patterns ────────────────────────────────────────────────────────────
IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b')
URL_PATTERN    = re.compile(r'https?://[^\s,\'"<>]+')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_PATTERN   = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32}\b')
EMAIL_PATTERN  = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def detect_hash_type(h):
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "hash")


def extract_iocs_from_text(text, source):
    results = []
    for url in URL_PATTERN.findall(text):
        results.append({"type": "url", "value": url.strip(), "source": source})
    for ip in IP_PATTERN.findall(text):
        if is_valid_ip(ip):
            results.append({"type": "ip", "value": ip.strip(), "source": source})
    for email in EMAIL_PATTERN.findall(text):
        results.append({"type": "email", "value": email.lower(), "source": source})
    for h in SHA256_PATTERN.findall(text):
        results.append({"type": "sha256", "value": h.lower(), "source": source})
    for h in SHA1_PATTERN.findall(text):
        results.append({"type": "sha1", "value": h.lower(), "source": source})
    for h in MD5_PATTERN.findall(text):
        results.append({"type": "md5", "value": h.lower(), "source": source})
    url_hosts   = set(re.findall(r'https?://([^/\s]+)', text))
    email_hosts = set(re.findall(r'@([a-zA-Z0-9.\-]+)', text))
    skip        = url_hosts | email_hosts
    for domain in DOMAIN_PATTERN.findall(text):
        if domain not in skip and not IP_PATTERN.match(domain):
            results.append({"type": "domain", "value": domain.lower(), "source": source})
    return results


def parse_txt(filepath):
    source  = os.path.basename(filepath)
    results = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            results.extend(extract_iocs_from_text(line, source))
    print(f"  [TXT]  {source:<35} -> {len(results):>4} raw IOCs")
    return results


def parse_csv(filepath):
    source  = os.path.basename(filepath)
    results = []
    TYPE_COLS  = ["type", "ioc_type", "indicator_type"]
    VALUE_COLS = ["indicator", "value", "ioc", "observable"]
    SEV_COLS   = ["severity", "risk", "confidence"]

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return results
        headers   = [h.lower().strip() for h in reader.fieldnames]
        type_col  = next((h for h in headers if h in TYPE_COLS), None)
        value_col = next((h for h in headers if h in VALUE_COLS), None)
        sev_col   = next((h for h in headers if h in SEV_COLS), None)

        for row in reader:
            r        = {k.lower().strip(): v.strip() for k, v in row.items()}
            value    = r.get(value_col, "") if value_col else ""
            itype    = r.get(type_col, "").lower() if type_col else ""
            severity = r.get(sev_col, "unknown").lower() if sev_col else "unknown"
            if not value:
                continue
            if itype == "hash":
                itype = detect_hash_type(value)
            if itype in ("ip", "domain", "url", "email", "md5", "sha1", "sha256"):
                results.append({"type": itype, "value": value,
                                 "source": source, "severity": severity})
            else:
                for ioc in extract_iocs_from_text(value, source):
                    ioc["severity"] = severity
                    results.append(ioc)

    print(f"  [CSV]  {source:<35} -> {len(results):>4} raw IOCs")
    return results


def parse_json(filepath):
    source  = os.path.basename(filepath)
    results = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    indicators = []
    if isinstance(data, list):
        indicators = data
    elif isinstance(data, dict):
        for key in ("indicators", "iocs", "data", "results", "objects"):
            if key in data and isinstance(data[key], list):
                indicators = data[key]
                break

    if not indicators:
        results = extract_iocs_from_text(json.dumps(data), source)
    else:
        for item in indicators:
            if not isinstance(item, dict):
                continue
            itype      = item.get("type", "").lower()
            value      = str(item.get("value", item.get("indicator", ""))).strip()
            confidence = item.get("confidence", 50)
            tags       = item.get("tags", [])
            if not value:
                continue
            if itype == "hash":
                itype = detect_hash_type(value)
            severity = ("high" if confidence >= 80
                        else "medium" if confidence >= 50 else "low")
            results.append({"type": itype, "value": value,
                             "source": source, "severity": severity, "tags": tags})

    print(f"  [JSON] {source:<35} -> {len(results):>4} raw IOCs")
    return results


def load_all_feeds(feeds_dir):
    print(f"\n{'='*60}")
    print("  STEP 1 -- LOADING & PARSING FEEDS")
    print(f"{'='*60}")

    parsers  = {".txt": parse_txt, ".csv": parse_csv, ".json": parse_json}
    all_iocs = []

    files = sorted([
        os.path.join(feeds_dir, f) for f in os.listdir(feeds_dir)
        if os.path.isfile(os.path.join(feeds_dir, f))
        and os.path.splitext(f)[1].lower() in parsers
    ])

    if not files:
        print("  WARNING: No feed files found in feeds/ directory.")
        return []

    for fp in files:
        ext    = os.path.splitext(fp)[1].lower()
        result = parsers[ext](fp)
        all_iocs.extend(result)

    print(f"\n  Total raw IOCs collected: {len(all_iocs)}")
    return all_iocs

"""
Module 4: Blocklist Generator
Produces category blocklists for firewalls, web filters,
EDR tools, and mail gateways. Exports TXT + CSV + JSON.
"""

import os
import csv
import json
from datetime import datetime, timezone


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _write_txt(path, lines, header=""):
    with open(path, "w", encoding="utf-8") as f:
        if header:
            for h in header.splitlines():
                f.write(f"# {h}\n")
            f.write("#\n")
        for line in lines:
            f.write(line + "\n")


def _write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_blocklists(correlated_iocs, output_dir):
    print(f"\n{'='*60}")
    print("  STEP 5 -- GENERATING BLOCKLISTS")
    print(f"{'='*60}")

    os.makedirs(output_dir, exist_ok=True)
    ts = _ts()

    ips     = [i for i in correlated_iocs if i["type"] == "ip"]
    domains = [i for i in correlated_iocs if i["type"] == "domain"]
    urls    = [i for i in correlated_iocs if i["type"] == "url"]
    hashes  = [i for i in correlated_iocs if i["type"] in ("md5","sha1","sha256","hash")]
    emails  = [i for i in correlated_iocs if i["type"] == "email"]
    web     = urls + domains

    FIELDS = ["type","value","final_severity","risk_score","feed_count","sources","tags"]

    def _save(name, rows, vals, label, use_case):
        hdr = f"{label}\nGenerated : {ts}\nEntries   : {len(vals)}\nUse for   : {use_case}"
        base = os.path.join(output_dir, name)
        _write_txt(base + ".txt", vals, hdr)
        _write_csv(base + ".csv", rows, FIELDS)
        _write_json(base + ".json", {"generated": ts, "count": len(rows), "blocklist": rows})
        print(f"  Saved  {name:<30} -> {len(rows):>4} entries  (txt / csv / json)")
        return len(rows)

    summary = {}
    summary["firewall_ips"]      = _save("firewall_blocklist",  ips,    [i["value"] for i in ips],
                                         "Firewall IP Blocklist",
                                         "iptables / pfSense / Cisco ACL")
    summary["web_filter"]        = _save("webfilter_blocklist", web,    [i["value"] for i in web],
                                         "Web Filter Blocklist (URLs + Domains)",
                                         "Proxy / DNS sinkhole / Web gateway")
    summary["edr_hashes"]        = _save("edr_hash_blocklist",  hashes, [i["value"] for i in hashes],
                                         "EDR / AV Hash Blocklist",
                                         "EDR custom rules / AV hash blacklist")
    summary["email_blocklist"]   = _save("email_blocklist",     emails, [i["value"] for i in emails],
                                         "Email / Spam Blocklist",
                                         "Mail gateway / SpamAssassin")
    return summary

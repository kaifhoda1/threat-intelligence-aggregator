<div align="center">

# Threat Intelligence Aggregator

**A Python-based Blue Team tool that collects, normalizes, correlates IOCs from multiple threat feeds and generates deployment-ready blocklists — with a live Flask web dashboard.**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-green?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> Built as part of the **Unified Mentor Cybersecurity Fellowship Program**

</div>

---

## What Is This?

Modern SOC teams receive threat data from dozens of sources daily — in different formats, with duplicates, and inconsistent structures. Analysts waste hours manually processing these feeds.

**Threat Intelligence Aggregator** solves this by automating the entire workflow:

```
Raw Feeds (TXT/CSV/JSON)  ->  Parse  ->  Normalize  ->  Correlate  ->  Blocklists + Report
```

In one command, it processes all your threat feeds and produces deployment-ready blocklists for your firewall, web proxy, EDR, and mail gateway.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/kaifhoda1/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Add your IOC feed files to feeds/
#    Supported formats: .txt  .csv  .json

# 4. Run the full pipeline (CLI)
python3 main.py

# 5. Launch the web dashboard
python3 dashboard.py
# Open http://localhost:5000 in your browser
```

---

## Project Structure

```
threat-intelligence-aggregator/
│
├── feeds/                           <- Drop your IOC feed files here
│   ├── feed1_ips.txt                <- Sample: malicious IP list
│   ├── feed2_mixed.csv              <- Sample: mixed IOCs (CSV format)
│   └── feed3_cert.json              <- Sample: CERT threat feed (JSON)
│
├── modules/                         <- Core pipeline modules
│   ├── parser.py                    <- Step 1: Parse TXT/CSV/JSON feeds
│   ├── normalizer.py                <- Step 2 & 3: Validate & deduplicate
│   ├── correlator.py                <- Step 4: Cross-feed correlation & scoring
│   ├── blocklist_gen.py             <- Step 5: Generate blocklists
│   └── reporter.py                  <- Step 6: Final TXT + JSON report
│
├── output/
│   ├── blocklists/                  <- 12 blocklist files (4 types x 3 formats)
│   └── reports/                     <- Threat intelligence reports
│
├── main.py                          <- CLI entry point
├── dashboard.py                     <- Flask web dashboard
└── requirements.txt
```

---

## How It Works — 6-Step Pipeline

| Step | Module | What It Does |
|------|--------|-------------|
| 1 | `parser.py` | Loads all feed files, auto-detects TXT/CSV/JSON format, extracts IOCs using regex |
| 2 | `normalizer.py` | Validates each IOC (IP format, domain structure, hash length, etc.) |
| 3 | `normalizer.py` | Deduplicates by (type, value) key, merges sources, upgrades severity |
| 4 | `correlator.py` | Calculates risk score (0-100), flags IOCs seen in 2+ feeds as correlated |
| 5 | `blocklist_gen.py` | Generates 4 category blocklists in TXT, CSV, and JSON formats |
| 6 | `reporter.py` | Produces full threat intelligence report in TXT and JSON |

---

## Supported IOC Types

| Type | Example | Validation Method |
|------|---------|------------------|
| IP Address | `185.220.101.45` | Python ipaddress module |
| Domain | `malware-c2.ru` | Regex + whitelist filter |
| URL | `http://evil.com/payload.exe` | HTTP/HTTPS prefix check |
| MD5 Hash | `d41d8cd98f00b204e9800998ecf8427e` | 32 char hex |
| SHA1 Hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | 40 char hex |
| SHA256 Hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4...` | 64 char hex |
| Email | `phisher@evil.com` | Regex validation |

---

## Risk Scoring Formula

Each IOC receives a risk score from 0 to 100 calculated as:

```
Risk Score = Feed Count Score (max 40)
           + Severity Score   (max 40)
           + IOC Type Weight  (max 20)
```

| Score Range | Severity | Action |
|------------|----------|--------|
| >= 70 | HIGH | Immediate action required |
| >= 40 | MEDIUM | Monitor and investigate |
| < 40  | LOW | Informational |

---

## Blocklist Output

| Blocklist File | IOC Types | Deploy To |
|---------------|-----------|-----------|
| `firewall_blocklist` | IP Addresses | iptables / pfSense / Cisco ACL |
| `webfilter_blocklist` | URLs + Domains | Proxy / DNS sinkhole / Zscaler |
| `edr_hash_blocklist` | MD5, SHA1, SHA256 | CrowdStrike / SentinelOne / Defender |
| `email_blocklist` | Email Addresses | Microsoft 365 / SpamAssassin |

Each blocklist is exported in 3 formats: `.txt` `.csv` `.json` — 12 files total.

---

## Sample Results

Running against the 3 included sample feeds:

```
Feeds Processed         : 3
Raw IOCs Collected      : 30
Duplicates Merged       : 10
Unique IOCs             : 20
HIGH Severity           : 9
MEDIUM Severity         : 7
LOW Severity            : 4
Cross-Feed Correlated   : 7
Blocklist Files Output  : 12
```

Top correlated indicators:

| Severity | Type | Score | Feeds | Indicator |
|----------|------|-------|-------|-----------|
| HIGH | ip | 99/100 | 3 | `185.220.101.45` |
| HIGH | ip | 99/100 | 3 | `45.142.212.100` |
| HIGH | ip | 84/100 | 3 | `91.108.4.1` |
| HIGH | domain | 82/100 | 2 | `malware-c2.ru` |
| MEDIUM | ip | 56/100 | 2 | `203.0.113.10` |

---

## Web Dashboard

Run `python3 dashboard.py` and open `http://localhost:5000`

Features:
- Live stat cards (Total IOCs, HIGH/MEDIUM/LOW counts, Cross-feed hits)
- IOC distribution bar chart by type
- Blocklist output summary
- Full searchable IOC table
- Filter by severity (HIGH / MEDIUM / LOW / Correlated)
- One-click Re-Run Analysis button

---

## Technologies Used

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| Flask | Web dashboard and REST API |
| re (regex) | IOC extraction patterns |
| ipaddress | IP validation |
| csv / json | Multi-format parsing and export |
| datetime | IOC timestamping |
| argparse | CLI argument handling |

---

## Feed File Formats

**TXT** — one IOC per line:
```
185.220.101.45
malware-c2.ru
http://evil.com/payload.exe
```

**CSV** — with headers:
```csv
type,indicator,severity
ip,185.220.101.45,high
domain,malware-c2.ru,high
url,http://evil.com/payload.exe,medium
```

**JSON** — indicators array:
```json
{
  "indicators": [
    {"type": "ip", "value": "185.220.101.45", "confidence": 90},
    {"type": "domain", "value": "malware-c2.ru", "confidence": 95}
  ]
}
```

---

## Learning Outcomes

- How IOCs are structured in real-world threat intelligence platforms
- Parsing and normalizing heterogeneous multi-format data feeds
- Cross-source correlation to identify high-confidence threats
- How SOC analysts consume and prioritize threat intelligence
- Generating and deploying blocklists to security controls
- Building security dashboards with Flask

---

## Author

**Mohammad Kaif**  
GitHub: [kaifhoda1](https://github.com/kaifhoda1)  
Fellowship: Unified Mentor Cybersecurity Program

---

<div align="center">
Star this repo if you found it useful.
</div>

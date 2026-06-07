# Threat Intelligence Aggregator

## Quick Start

### 1. Install dependencies
pip3 install -r requirements.txt

### 2. Add your feed files to feeds/
Supported: .txt  .csv  .json

### 3. Run the CLI
python3 main.py

### 4. Run the Web Dashboard
python3 dashboard.py
Then open: http://localhost:5000

## Project Structure

ti_aggregator/
├── feeds/                  ← Put IOC feed files here
│   ├── feed1_ips.txt
│   ├── feed2_mixed.csv
│   └── feed3_cert.json
├── modules/
│   ├── parser.py           ← Parses TXT/CSV/JSON feeds
│   ├── normalizer.py       ← Cleans & deduplicates IOCs
│   ├── correlator.py       ← Cross-feed correlation & scoring
│   ├── blocklist_gen.py    ← Generates blocklists
│   └── reporter.py         ← Final TI report
├── output/
│   ├── blocklists/         ← Firewall / Web / EDR / Email blocklists
│   └── reports/            ← TXT & JSON threat reports
├── main.py                 ← CLI entry point
├── dashboard.py            ← Web dashboard (Flask)
└── requirements.txt

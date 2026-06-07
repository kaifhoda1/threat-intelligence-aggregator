"""
Threat Intelligence Aggregator — CLI Entry Point
Run: python3 main.py
"""

import os
import sys
import json
import argparse

# Make sure modules/ is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.parser       import load_all_feeds
from modules.normalizer   import normalize_all
from modules.correlator   import correlate
from modules.blocklist_gen import generate_blocklists
from modules.reporter     import generate_report

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
FEEDS_DIR     = os.path.join(BASE_DIR, "feeds")
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")
BLOCKLIST_DIR = os.path.join(OUTPUT_DIR, "blocklists")
REPORT_DIR    = os.path.join(OUTPUT_DIR, "reports")


def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║      THREAT INTELLIGENCE AGGREGATOR  v1.0               ║
║      IOC Collection | Correlation | Blocklist Gen        ║
╚══════════════════════════════════════════════════════════╝
""")


def run_pipeline(feeds_dir=FEEDS_DIR):
    banner()

    # Step 1 — Parse feeds
    raw_iocs = load_all_feeds(feeds_dir)
    if not raw_iocs:
        print("\n[ERROR] No IOCs loaded. Add feed files to the feeds/ directory.")
        sys.exit(1)

    # Step 2 & 3 — Normalize & deduplicate
    normalized = normalize_all(raw_iocs)

    # Step 4 — Correlate
    correlated = correlate(normalized)

    # Step 5 — Generate blocklists
    bl_summary = generate_blocklists(correlated, BLOCKLIST_DIR)

    # Step 6 — Generate reports
    txt_path, json_path = generate_report(
        correlated, bl_summary, feeds_dir, REPORT_DIR
    )

    print(f"\n{'='*60}")
    print("  PIPELINE COMPLETE")
    print(f"{'='*60}")
    print(f"  Blocklists : {BLOCKLIST_DIR}")
    print(f"  Reports    : {REPORT_DIR}")
    print(f"\n  Run the dashboard for a visual view:")
    print(f"    python3 dashboard.py\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--feeds", default=FEEDS_DIR,
        help=f"Path to feeds directory (default: {FEEDS_DIR})"
    )
    parser.add_argument(
        "--show-high", action="store_true",
        help="After pipeline, print all HIGH severity IOCs to terminal"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(feeds_dir=args.feeds)

    if args.show_high:
        report_file = os.path.join(REPORT_DIR, "threat_intelligence_report.json")
        if os.path.exists(report_file):
            with open(report_file) as f:
                data = json.load(f)
            high = data.get("high_risk_iocs", [])
            print(f"\n  HIGH Severity IOCs ({len(high)} total):")
            print(f"  {'Type':<10} {'Score':>5}  Value")
            print(f"  {'-'*50}")
            for ioc in high:
                print(f"  {ioc['type']:<10} {ioc['risk_score']:>5}  {ioc['value']}")

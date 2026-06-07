"""
Module 5: Reporting Module
Generates a full threat intelligence report in TXT and JSON formats.
"""

import os
import json
from datetime import datetime, timezone


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_report(correlated_iocs, blocklist_summary, feeds_dir, output_dir):
    print(f"\n{'='*60}")
    print("  STEP 6 -- GENERATING REPORT")
    print(f"{'='*60}")

    os.makedirs(output_dir, exist_ok=True)
    ts = _ts()

    # ── Stats ───────────────────────────────────────────────────────────────────
    total        = len(correlated_iocs)
    high_iocs    = [i for i in correlated_iocs if i["final_severity"] == "HIGH"]
    medium_iocs  = [i for i in correlated_iocs if i["final_severity"] == "MEDIUM"]
    low_iocs     = [i for i in correlated_iocs if i["final_severity"] == "LOW"]
    corr_iocs    = [i for i in correlated_iocs if i["is_correlated"]]

    type_counts  = {}
    for ioc in correlated_iocs:
        type_counts[ioc["type"]] = type_counts.get(ioc["type"], 0) + 1

    feed_files   = [f for f in os.listdir(feeds_dir) if os.path.isfile(os.path.join(feeds_dir, f))]

    # ── TXT Report ──────────────────────────────────────────────────────────────
    txt_path = os.path.join(output_dir, "threat_intelligence_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write("     THREAT INTELLIGENCE AGGREGATOR — FINAL REPORT\n")
        f.write("=" * 65 + "\n")
        f.write(f"  Generated : {ts}\n\n")

        f.write("SECTION 1 — FEED SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Feeds processed  : {len(feed_files)}\n")
        for ff in sorted(feed_files):
            f.write(f"    - {ff}\n")

        f.write("\nSECTION 2 — IOC STATISTICS\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Total unique IOCs : {total}\n")
        f.write(f"  HIGH severity     : {len(high_iocs)}\n")
        f.write(f"  MEDIUM severity   : {len(medium_iocs)}\n")
        f.write(f"  LOW severity      : {len(low_iocs)}\n")
        f.write(f"  Cross-feed hits   : {len(corr_iocs)}\n")
        f.write("\n  Breakdown by type:\n")
        for t, c in sorted(type_counts.items()):
            f.write(f"    {t:<12} : {c}\n")

        f.write("\nSECTION 3 — HIGH-RISK INDICATORS (TOP 20)\n")
        f.write("-" * 40 + "\n")
        f.write(f"  {'Type':<8} {'Score':>5}  {'Feeds':>5}  {'Value'}\n")
        f.write(f"  {'-'*55}\n")
        for ioc in high_iocs[:20]:
            f.write(f"  {ioc['type']:<8} {ioc['risk_score']:>5}  "
                    f"{ioc['feed_count']:>5}  {ioc['value']}\n")

        f.write("\nSECTION 4 — CORRELATED INDICATORS (SEEN IN 2+ FEEDS)\n")
        f.write("-" * 40 + "\n")
        if corr_iocs:
            for ioc in corr_iocs[:30]:
                f.write(f"  [{ioc['final_severity']:<6}] {ioc['type']:<8}  "
                        f"score={ioc['risk_score']:>3}  feeds={ioc['feed_count']}  "
                        f"{ioc['value']}\n")
                f.write(f"           Sources: {', '.join(ioc['sources'])}\n")
        else:
            f.write("  No cross-feed correlations found.\n")

        f.write("\nSECTION 5 — BLOCKLIST SUMMARY\n")
        f.write("-" * 40 + "\n")
        for bl_name, count in blocklist_summary.items():
            f.write(f"  {bl_name:<25} : {count} entries\n")

        f.write("\n" + "=" * 65 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 65 + "\n")

    # ── JSON Report ─────────────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, "threat_intelligence_report.json")
    report_data = {
        "generated":          ts,
        "feeds_processed":    feed_files,
        "total_unique_iocs":  total,
        "severity_counts":    {"HIGH": len(high_iocs), "MEDIUM": len(medium_iocs), "LOW": len(low_iocs)},
        "type_counts":        type_counts,
        "correlated_count":   len(corr_iocs),
        "blocklist_summary":  blocklist_summary,
        "high_risk_iocs":     high_iocs[:50],
        "correlated_iocs":    corr_iocs[:50],
        "all_iocs":           correlated_iocs,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"  TXT  report -> {txt_path}")
    print(f"  JSON report -> {json_path}")
    return txt_path, json_path

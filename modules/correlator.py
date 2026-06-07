"""
Module 3: IOC Correlation Engine
Identifies IOCs across multiple feeds, calculates risk scores,
and flags high-priority correlated indicators.
"""

SEV_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


def calculate_risk_score(ioc):
    """
    Risk score 0-100:
      Feed count score  (max 40)
      Severity score    (max 40)
      Type weight       (max 20)
    """
    feed_count = len(set(ioc.get("sources", [ioc.get("source", "")])))

    feed_score = min(feed_count * 13, 40)

    sev_map   = {"high": 40, "medium": 25, "low": 10, "unknown": 5}
    sev_score = sev_map.get(ioc.get("severity", "unknown"), 5)

    type_map   = {
        "ip": 20, "url": 18, "domain": 16,
        "sha256": 15, "sha1": 13, "md5": 12, "hash": 12, "email": 10
    }
    type_score = type_map.get(ioc.get("type", ""), 10)

    return min(feed_score + sev_score + type_score, 100)


def assign_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def correlate(normalized_iocs):
    print(f"\n{'='*60}")
    print("  STEP 4 -- CORRELATION ENGINE")
    print(f"{'='*60}")

    high = medium = low = correlated_count = 0

    for ioc in normalized_iocs:
        sources    = list(set(ioc.get("sources", [ioc.get("source", "unknown")])))
        feed_count = len(sources)
        score      = calculate_risk_score(ioc)
        severity   = assign_severity(score)

        ioc["feed_count"]     = feed_count
        ioc["risk_score"]     = score
        ioc["final_severity"] = severity
        ioc["is_correlated"]  = feed_count >= 2
        ioc["sources"]        = sources

        if severity == "HIGH":   high   += 1
        if severity == "MEDIUM": medium += 1
        if severity == "LOW":    low    += 1
        if ioc["is_correlated"]: correlated_count += 1

    # Sort: correlated first, then by risk score descending
    normalized_iocs.sort(key=lambda x: (not x["is_correlated"], -x["risk_score"]))

    print(f"  Total IOCs analyzed:        {len(normalized_iocs)}")
    print(f"  Cross-feed correlated:      {correlated_count}")
    print(f"  HIGH severity:              {high}")
    print(f"  MEDIUM severity:            {medium}")
    print(f"  LOW severity:               {low}")

    top = [i for i in normalized_iocs if i["is_correlated"]][:10]
    if top:
        print(f"\n  Top correlated indicators (seen in 2+ feeds):")
        print(f"  {'Severity':<8} {'Type':<8} {'Score':>5}  {'Feeds':>5}  Indicator")
        print(f"  {'-'*55}")
        for ioc in top:
            print(f"  {ioc['final_severity']:<8} {ioc['type']:<8} "
                  f"{ioc['risk_score']:>5}  {ioc['feed_count']:>5}  {ioc['value']}")

    return normalized_iocs

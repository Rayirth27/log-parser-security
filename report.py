from collections import Counter
from parser import LogEntry
from detector import Detection

def generate_report(entries, detections, threshold) -> str:
    if not entries:
        return "No log entries to analyse."
    total        = len(entries)
    unique_ips   = len(set(e.ip for e in entries))
    status_count = Counter(e.status for e in entries)
    top_5        = Counter(e.ip for e in entries).most_common(5)
    lines = [
        "", "=" * 60, " SECURITY LOG ANALYSIS REPORT", "=" * 60,
        f" Total events:  {total}",
        f" Unique IPs:    {unique_ips}",
        f" Flagged IPs:   {len(detections)} (threshold: {threshold} failures)",
        "", " Status code breakdown:",
    ]
    for code in sorted(status_count.keys()):
        lines.append(f"   HTTP {code}: {status_count[code]} occurrences")
    lines += ["", " Top 5 IPs by request volume:"]
    for ip, count in top_5:
        flagged = "  WARNING: FLAGGED" if any(d.ip == ip for d in detections) else ""
        lines.append(f"   {ip:<20} {count} requests{flagged}")
    if detections:
        lines += ["", "=" * 60, " BRUTE FORCE DETECTIONS — MITRE T1110.001", "=" * 60]
        for d in detections:
            lines += [
                "", f"   IP:        {d.ip}",
                f"   Failures:  {d.failure_count}",
                f"   Technique: {d.technique}",
                f"   Detail:    {d.description}"
            ]
    lines.append("=" * 60)
    return "\n".join(lines)
import argparse, sys, json
from parser import parse_file
from detector import detect_brute_force
from report import generate_report, generate_json_report
from ai_analyzer import analyse_threat

def main():
    ap = argparse.ArgumentParser(
        description='Security log analyser — detects brute force (MITRE T1110)',
        epilog="""Examples:
  python main.py access.log
  python main.py access.log --threshold 5
  python main.py access.log --threshold 5 --output report.txt
  python main.py access.log --format json
  python main.py access.log --ai-analysis""")
    ap.add_argument('logfile')
    ap.add_argument('--threshold', type=int, default=10)
    ap.add_argument('--output',    default=None)
    ap.add_argument('--format', choices=['text', 'json'], default='text',
                 help='Output format: human-readable text or machine-readable JSON')
    ap.add_argument('--ai-analysis', action='store_true',
                 help='Send report summary to LLM for AI-powered threat analysis')
    args = ap.parse_args()

    print(f"[+] Parsing {args.logfile}...")
    try:
        entries = parse_file(args.logfile)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}"); sys.exit(1)

    print(f"[+] Parsed {len(entries)} valid log entries")
    detections = detect_brute_force(entries, args.threshold)

    ai_result = None
    if args.ai_analysis:
        print("[+] Sending summary to Claude for AI analysis...")
        text_summary = generate_report(entries, detections, args.threshold)
        ai_result = analyse_threat(text_summary)
        if "error" in ai_result:
            print(f"[!] AI analysis failed: {ai_result['error']}")
            ai_result = None

    if args.format == 'json':
        report_data = generate_json_report(entries, detections, args.threshold)
        if ai_result:
            report_data["ai_analysis"] = ai_result
        report = json.dumps(report_data, indent=2)
    else:
        report = generate_report(entries, detections, args.threshold)
        if ai_result:
            report += "\n\n=== AI Threat Analysis ===\n"
            report += f"Threat Level:       {ai_result.get('threat_level')}\n"
            report += f"Attack Type:        {ai_result.get('attack_type')}\n"
            report += f"Recommended Action: {ai_result.get('recommended_action')}\n"
            report += f"MITRE Technique:    {ai_result.get('mitre_technique')}\n"

    if args.output:
        with open(args.output, 'w') as f: f.write(report)
        print(f"[+] Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()
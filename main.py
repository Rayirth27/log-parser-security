import argparse, sys
from parser import parse_file
from detector import detect_brute_force
from report import generate_report

def main():
    ap = argparse.ArgumentParser(
        description='Security log analyser — detects brute force (MITRE T1110)',
        epilog="""Examples:
  python main.py access.log
  python main.py access.log --threshold 5
  python main.py access.log --threshold 5 --output report.txt""")
    ap.add_argument('logfile')
    ap.add_argument('--threshold', type=int, default=10)
    ap.add_argument('--output',    default=None)
    args = ap.parse_args()

    print(f"[+] Parsing {args.logfile}...")
    try:
        entries = parse_file(args.logfile)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}"); sys.exit(1)

    print(f"[+] Parsed {len(entries)} valid log entries")
    detections = detect_brute_force(entries, args.threshold)
    report     = generate_report(entries, detections, args.threshold)

    if args.output:
        with open(args.output, 'w') as f: f.write(report)
        print(f"[+] Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: str
    size: str
    raw: str

IP_PATTERN = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
TIMESTAMP_PATTERN = r'\[([^\]]+)\]' #[20/May/2015:17:05:33 +0000]
REQUEST_PATTERN  = r'"([A-Z]+) ([^\s]+) HTTP'
STATUS_PATTERN = r'" (\d{3}) '
SIZE_PATTERN = r'" \d{3} (\d+)'

def parse_line(line: str) -> Optional[LogEntry]:
    #Parse one Apache log line. Return None if malformed - never crash.
    if not line.strip():
        return None
    
    ip_m = re.search(IP_PATTERN,line)
    ts_m = re.search(TIMESTAMP_PATTERN, line)
    req_m = re.search(REQUEST_PATTERN,line)
    st_m = re.search(STATUS_PATTERN, line)
    sz_m = re.search(SIZE_PATTERN,line)
    if not ip_m or not st_m:
        return None
    return LogEntry(
        ip = ip_m.group(1),
        timestamp = ts_m.group(1) if ts_m else "unknown",
        method = req_m.group(1) if req_m else "unknown",
        path = req_m.group(2) if req_m else "unknown",
        status = st_m.group(1),
        size = sz_m.group(1) if sz_m else "0",
        raw = line.strip()
    )

def parse_file(filepath: str) -> list[LogEntry]:
    #Read file line by line. Skip invalid lines, never crash.
    entries, skipped = [], 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    entries.append(entry)
                else:
                    skipped += 1
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {filepath}")
    if skipped > 0:
        print(f"[parser] Skipped {skipped} malformed lines")
    return entries
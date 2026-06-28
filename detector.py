from collections import Counter
from dataclasses import dataclass
from parser import LogEntry

#Repeated auth failures from a single IP = priamry indicator of T1110.001
AUTH_FAILURE_CODES = {"401","403"}

@dataclass
class Detection:
    ip : str
    count : int 
    failure_count: int
    technique: str
    description:str

def detect_brute_force(entries: list[LogEntry], threshold: int = 10) -> list[Detection]: #threshold is 10 it's a default, not a tuned value — real tuning would come from analyzing actual traffic for that specific system."
    failure_counter = Counter(
        e.ip for e in entries if e.status in AUTH_FAILURE_CODES
    )
    detections = []
    for ip,failure_count in failure_counter.items():
        if failure_count > threshold:
            total_count = sum(1 for e in entries if e.ip == ip)
            detections.append(Detection(
                ip =ip,
                count = total_count,
                failure_count = failure_count,
                technique= "T1110.001",
                description = (
                    f"{failure_count} auth failures ({total_count} total requests). "
                    f"Consistent with MITRE ATT&CK T1110.001 - Password Guessing."
                )
            ))
    return sorted(detections, key=lambda d: d.failure_count, reverse=True)
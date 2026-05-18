from collections import defaultdict
from config import BRUTE_FORCE_THRESHOLD
from threat_intel import check_threat_intel


def analyze_events(parsed_logs):
    failed_logins = defaultdict(int)
    successful_logins = 0
    events = []
    alerts = []

    for log in parsed_logs:
        event_type = log["event_type"]
        ip = log["ip"]

        severity = "LOW"

        if event_type == "LOGIN_FAILED":
            failed_logins[ip] += 1

            if failed_logins[ip] >= BRUTE_FORCE_THRESHOLD:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        elif event_type == "LOGIN_SUCCESS":
            successful_logins += 1

        threat_info = check_threat_intel(ip)

        event = {
            "timestamp": log["timestamp"],
            "event_type": event_type,
            "user": log["user"],
            "ip": ip,
            "severity": severity,
            "threat_intel": threat_info
        }

        events.append(event)

    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alert = {
                "ip": ip,
                "failed_attempts": count,
                "threat_level": "HIGH",
                "alert": f"Potential brute-force attack detected from IP {ip}",
                "threat_intel": check_threat_intel(ip)
            }

            alerts.append(alert)

    failed_events = sum(failed_logins.values())
    suspicious_ips = len(alerts)

    soc_score = 100
    soc_score -= suspicious_ips * 25
    soc_score -= failed_events * 3

    if soc_score < 0:
        soc_score = 0

    summary = {
        "total_events": len(events),
        "successful_logins": successful_logins,
        "failed_logins": failed_events,
        "suspicious_ips": suspicious_ips,
        "soc_score": soc_score
    }

    return summary, events, alerts
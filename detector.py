from collections import Counter
from threat_intel import THREAT_INTEL


MITRE_ATTACK_MAPPING = {
    "LOGIN_FAILED": "T1110 - Brute Force",
    "LOGIN_SUCCESS": "T1078 - Valid Accounts"
}


COUNTRY_MAP = {
    "185.220.101.45": "Germany",
    "91.200.12.77": "Russia",
    "45.33.32.156": "United States",
    "192.168.1.10": "Internal Network",
    "192.168.1.20": "Internal Network"
}


def detect_brute_force(events, threshold):
    failed_ips = []

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            failed_ips.append(event["ip"])

    ip_counter = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counter.items():

        if count >= threshold:

            threat_intel = THREAT_INTEL.get(ip, "Unknown")

            if count >= 5:
                threat_level = "CRITICAL"
            elif count >= 4:
                threat_level = "HIGH"
            else:
                threat_level = "MEDIUM"

            ml_score = min(count * 20, 100)

            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "threat_level": threat_level,
                "threat_intel": threat_intel,
                "country": COUNTRY_MAP.get(ip, "Unknown"),
                "mitre_attack": "T1110 - Brute Force",
                "ml_threat_score": ml_score,
                "alert": f"Potential brute-force attack detected from IP {ip}"
            })

    return alerts


def enrich_events(events):

    ip_counter = Counter()

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            ip_counter[event["ip"]] += 1

    enriched = []

    for event in events:

        threat_intel = THREAT_INTEL.get(event["ip"], "N/A")
        failed_count = ip_counter[event["ip"]]

        if failed_count >= 5:
            severity = "CRITICAL"
        elif failed_count >= 3:
            severity = "HIGH"
        elif failed_count >= 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        anomaly = False

        if event["user"].lower() in ["admin", "root", "hacker"]:
            anomaly = True

        ml_score = min((failed_count * 15) + (20 if anomaly else 0), 100)

        enriched.append({
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "user": event["user"],
            "ip": event["ip"],
            "severity": severity,
            "threat_intel": threat_intel,
            "country": COUNTRY_MAP.get(event["ip"], "Unknown"),
            "mitre_attack": MITRE_ATTACK_MAPPING.get(
                event["event_type"],
                "Unknown"
            ),
            "anomaly_detected": anomaly,
            "ml_threat_score": ml_score
        })

    return enriched


def calculate_soc_score(events, alerts):

    score = 100

    high_events = len([
        event for event in events
        if event["severity"] in ["HIGH", "CRITICAL"]
    ])

    suspicious_ips = len(alerts)

    score -= high_events * 7
    score -= suspicious_ips * 10

    return max(score, 0)


def generate_heatmap(events):

    heatmap = {}

    for event in events:

        hour = event["timestamp"].split(" ")[1].split(":")[0]
        ip = event["ip"]

        key = f"{hour}:00 - {ip}"

        if key not in heatmap:
            heatmap[key] = 0

        heatmap[key] += 1

    return heatmap
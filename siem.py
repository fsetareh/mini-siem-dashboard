from colorama import Fore, init
import time

from config import LOG_FILE, MONITOR_INTERVAL, BRUTE_FORCE_THRESHOLD
from parser import read_logs, parse_log_line
from detector import (
    enrich_events,
    detect_brute_force,
    calculate_soc_score,
    generate_heatmap
)
from reporter import generate_all_reports

init(autoreset=True)

processed_logs = set()

print(Fore.CYAN + "\n=== Mini SIEM Dashboard V16 - Modular SOC Version ===")
print(Fore.CYAN + "Real-time monitoring started...")
print(Fore.CYAN + "Press Ctrl + C to stop.\n")

while True:
    logs = read_logs(LOG_FILE)

    new_logs = []

    for log in logs:
        if log not in processed_logs:
            new_logs.append(log)
            processed_logs.add(log)

    if new_logs:
        parsed_logs = []

        for log in logs:
            parsed_logs.append(parse_log_line(log))

        events = enrich_events(parsed_logs)

        alerts = detect_brute_force(
            events,
            BRUTE_FORCE_THRESHOLD
        )

        heatmap = generate_heatmap(events)

        soc_score = calculate_soc_score(events, alerts)

        successful_logins = len([
            event for event in events
            if event["event_type"] == "LOGIN_SUCCESS"
        ])

        failed_logins = len([
            event for event in events
            if event["event_type"] == "LOGIN_FAILED"
        ])

        summary = {
            "total_events": len(events),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "suspicious_ips": len(alerts),
            "soc_score": soc_score
        }

        print(Fore.CYAN + "\n=== New Logs Detected ===\n")

        for log in new_logs:
            parsed = parse_log_line(log)

            if parsed["event_type"] == "LOGIN_FAILED":
                print(
                    Fore.RED +
                    f"[FAILED] {parsed['timestamp']} | "
                    f"User: {parsed['user']} | "
                    f"IP: {parsed['ip']}"
                )

            elif parsed["event_type"] == "LOGIN_SUCCESS":
                print(
                    Fore.GREEN +
                    f"[SUCCESS] {parsed['timestamp']} | "
                    f"User: {parsed['user']} | "
                    f"IP: {parsed['ip']}"
                )

        print(Fore.CYAN + "\n=== Summary ===")
        print(Fore.CYAN + f"Total Events: {summary['total_events']}")
        print(Fore.GREEN + f"Successful Logins: {summary['successful_logins']}")
        print(Fore.RED + f"Failed Logins: {summary['failed_logins']}")
        print(Fore.YELLOW + f"Suspicious IPs: {summary['suspicious_ips']}")
        print(Fore.GREEN + f"SOC Score: {summary['soc_score']}/100")

        for alert in alerts:
            print(Fore.RED + f"[ALERT] {alert['alert']}")
            print(Fore.MAGENTA + f"[THREAT INTEL] {alert['threat_intel']}")
            print(Fore.YELLOW + f"[MITRE] {alert['mitre_attack']}")
            print(Fore.CYAN + f"[ML SCORE] {alert['ml_threat_score']}/100")

        generate_all_reports(
            summary,
            events,
            alerts,
            heatmap
        )

        print(Fore.CYAN + "\nReports updated:")
        print(Fore.CYAN + "- reports/security_report.txt")
        print(Fore.CYAN + "- reports/siem_results.json")
        print(Fore.CYAN + "- reports/dashboard.html")

    time.sleep(MONITOR_INTERVAL)
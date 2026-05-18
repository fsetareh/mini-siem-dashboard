import json
import os
from config import REPORT_FILE, JSON_FILE, HTML_FILE

os.makedirs("reports", exist_ok=True)


def generate_text_report(summary, events, alerts):
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("=== MINI SIEM SECURITY REPORT V8 ===\n\n")

        report.write("=== Summary ===\n\n")
        for key, value in summary.items():
            report.write(f"{key}: {value}\n")

        report.write("\n=== Alerts ===\n\n")
        for alert in alerts:
            report.write(
                f"IP: {alert['ip']} | "
                f"Failed Attempts: {alert['failed_attempts']} | "
                f"Threat Level: {alert['threat_level']} | "
                f"Threat Intel: {alert['threat_intel']} | "
                f"{alert['alert']}\n"
            )

        report.write("\n=== Events ===\n\n")
        for event in events:
            report.write(
                f"{event['timestamp']} | "
                f"{event['event_type']} | "
                f"user={event['user']} | "
                f"ip={event['ip']} | "
                f"severity={event['severity']} | "
                f"threat_intel={event['threat_intel']}\n"
            )


def generate_json_report(summary, events, alerts):
    with open(JSON_FILE, "w", encoding="utf-8") as json_file:
        json.dump(
            {
                "summary": summary,
                "alerts": alerts,
                "events": events
            },
            json_file,
            indent=4
        )


def generate_html_dashboard(summary, events, alerts):
    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>Mini SIEM Dashboard</title>
<style>
body {{
    font-family: Arial;
    background-color: #111827;
    color: white;
    padding: 20px;
}}
h1, h2 {{
    color: #38bdf8;
}}
.card {{
    background-color: #1f2937;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    border: 1px solid #374151;
    padding: 10px;
}}
th {{
    background-color: #0f172a;
}}
.HIGH {{
    color: #f87171;
    font-weight: bold;
}}
.MEDIUM {{
    color: #facc15;
    font-weight: bold;
}}
.LOW {{
    color: #4ade80;
    font-weight: bold;
}}
</style>
</head>
<body>

<h1>Mini SIEM Dashboard V8</h1>

<div class="card">
<p><strong>Total Events:</strong> {summary["total_events"]}</p>
<p><strong>Successful Logins:</strong> {summary["successful_logins"]}</p>
<p><strong>Failed Logins:</strong> {summary["failed_logins"]}</p>
<p><strong>Suspicious IPs:</strong> {summary["suspicious_ips"]}</p>
<p><strong>SOC Security Score:</strong> {summary["soc_score"]}/100</p>
</div>

<h2>Alerts</h2>

<table>
<tr>
<th>IP</th>
<th>Failed Attempts</th>
<th>Threat Level</th>
<th>Threat Intel</th>
<th>Alert</th>
</tr>
"""

    for alert in alerts:
        html += f"""
<tr>
<td>{alert["ip"]}</td>
<td>{alert["failed_attempts"]}</td>
<td class="{alert["threat_level"]}">{alert["threat_level"]}</td>
<td>{alert["threat_intel"]}</td>
<td>{alert["alert"]}</td>
</tr>
"""

    html += """
</table>

<h2>Event Logs</h2>

<table>
<tr>
<th>Timestamp</th>
<th>Event</th>
<th>User</th>
<th>IP</th>
<th>Severity</th>
<th>Threat Intel</th>
</tr>
"""

    for event in events:
        html += f"""
<tr>
<td>{event["timestamp"]}</td>
<td>{event["event_type"]}</td>
<td>{event["user"]}</td>
<td>{event["ip"]}</td>
<td class="{event["severity"]}">{event["severity"]}</td>
<td>{event["threat_intel"]}</td>
</tr>
"""

    html += """
</table>

</body>
</html>
"""

    with open(HTML_FILE, "w", encoding="utf-8") as html_file:
        html_file.write(html)


def generate_all_reports(summary, events, alerts):
    generate_text_report(summary, events, alerts)
    generate_json_report(summary, events, alerts)
    generate_html_dashboard(summary, events, alerts)
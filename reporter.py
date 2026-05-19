import json
import os
from collections import Counter
from config import REPORT_FILE, JSON_FILE, HTML_FILE


os.makedirs("reports", exist_ok=True)


def generate_text_report(summary, events, alerts, heatmap):
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("=== MINI SIEM SECURITY REPORT V16 ===\n\n")

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
                f"Country: {alert['country']} | "
                f"MITRE: {alert['mitre_attack']} | "
                f"ML Score: {alert['ml_threat_score']} | "
                f"{alert['alert']}\n"
            )

        report.write("\n=== Attack Heatmap ===\n\n")
        for key, value in heatmap.items():
            report.write(f"{key}: {value} events\n")

        report.write("\n=== Events ===\n\n")
        for event in events:
            report.write(
                f"{event['timestamp']} | "
                f"{event['event_type']} | "
                f"user={event['user']} | "
                f"ip={event['ip']} | "
                f"severity={event['severity']} | "
                f"threat_intel={event['threat_intel']} | "
                f"country={event['country']} | "
                f"mitre={event['mitre_attack']} | "
                f"anomaly={event['anomaly_detected']} | "
                f"ml_score={event['ml_threat_score']}\n"
            )


def generate_json_report(summary, events, alerts, heatmap):
    with open(JSON_FILE, "w", encoding="utf-8") as json_file:
        json.dump(
            {
                "summary": summary,
                "alerts": alerts,
                "heatmap": heatmap,
                "events": events
            },
            json_file,
            indent=4
        )


def generate_html_dashboard(summary, events, alerts, heatmap):
    severity_counts = Counter(event["severity"] for event in events)
    event_type_counts = Counter(event["event_type"] for event in events)
    country_counts = Counter(event["country"] for event in events)

    low_count = severity_counts.get("LOW", 0)
    medium_count = severity_counts.get("MEDIUM", 0)
    high_count = severity_counts.get("HIGH", 0)
    critical_count = severity_counts.get("CRITICAL", 0)

    success_count = event_type_counts.get("LOGIN_SUCCESS", 0)
    failed_count = event_type_counts.get("LOGIN_FAILED", 0)

    countries = list(country_counts.keys())
    country_values = list(country_counts.values())

    score_class = "score-good"

    if summary["soc_score"] < 40:
        score_class = "score-danger"
    elif summary["soc_score"] < 70:
        score_class = "score-warning"

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>Mini SIEM Dashboard V16</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #111827;
    color: #f9fafb;
    padding: 20px;
}}

h1, h2 {{
    color: #38bdf8;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}

.card {{
    background-color: #1f2937;
    padding: 18px;
    border-radius: 12px;
    box-shadow: 0 0 10px rgba(0,0,0,0.25);
}}

.card h3 {{
    margin: 0;
    color: #93c5fd;
    font-size: 16px;
}}

.card p {{
    font-size: 28px;
    font-weight: bold;
    margin: 10px 0 0 0;
}}

.score-good {{
    color: #4ade80;
}}

.score-warning {{
    color: #facc15;
}}

.score-danger {{
    color: #f87171;
}}

.chart-section {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
    margin-bottom: 25px;
}}

.chart-card {{
    background-color: #1f2937;
    padding: 20px;
    border-radius: 12px;
    min-height: 420px;
}}

.chart-card canvas {{
    max-height: 320px !important;
    width: 100% !important;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background-color: #1f2937;
    margin-bottom: 25px;
}}

th, td {{
    border: 1px solid #374151;
    padding: 10px;
    text-align: left;
}}

th {{
    background-color: #0f172a;
    position: sticky;
    top: 0;
}}

.CRITICAL {{
    color: #fb7185;
    font-weight: bold;
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

.print-button {{
    background-color: #38bdf8;
    color: #0f172a;
    padding: 10px 16px;
    border: none;
    border-radius: 8px;
    font-weight: bold;
    cursor: pointer;
    margin-bottom: 20px;
}}

.footer {{
    color: #9ca3af;
    font-size: 13px;
    margin-top: 20px;
}}

@media print {{
    body {{
        background-color: white;
        color: black;
        zoom: 70%;
        padding: 10px;
    }}

    h1, h2 {{
        color: #1f7895;
    }}

    .grid {{
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
    }}

    .card,
    .chart-card,
    table {{
        background-color: white;
        color: black;
        box-shadow: none;
    }}

    .chart-section {{
        display: block;
    }}

    .chart-card {{
        page-break-inside: avoid;
        margin-bottom: 25px;
        min-height: 350px;
    }}

    canvas {{
        max-height: 260px !important;
        width: 100% !important;
    }}

    table {{
        page-break-inside: auto;
        font-size: 11px;
    }}

    th {{
        background-color: #e5e7eb;
        color: black;
    }}

    .print-button {{
        display: none;
    }}

    .footer {{
        color: #444;
    }}
}}
</style>
</head>

<body>

<h1>Mini SIEM Dashboard V16</h1>

<button class="print-button" onclick="window.print()">Export / Print PDF</button>

<div class="grid">
    <div class="card">
        <h3>Total Events</h3>
        <p>{summary["total_events"]}</p>
    </div>

    <div class="card">
        <h3>Failed Logins</h3>
        <p class="score-danger">{summary["failed_logins"]}</p>
    </div>

    <div class="card">
        <h3>Suspicious IPs</h3>
        <p class="score-warning">{summary["suspicious_ips"]}</p>
    </div>

    <div class="card">
        <h3>SOC Score</h3>
        <p class="{score_class}">{summary["soc_score"]}/100</p>
    </div>
</div>

<div class="chart-section">

    <div class="chart-card">
        <h2>Severity Distribution</h2>
        <canvas id="severityChart"></canvas>
    </div>

    <div class="chart-card">
        <h2>Login Result Distribution</h2>
        <canvas id="loginChart"></canvas>
    </div>

    <div class="chart-card">
        <h2>Geo-IP Simulation</h2>
        <canvas id="countryChart"></canvas>
    </div>

    <div class="chart-card">
        <h2>Attack Heatmap</h2>
        <table>
            <tr>
                <th>Hour / IP</th>
                <th>Events</th>
            </tr>
"""

    for key, value in heatmap.items():
        html += f"""
            <tr>
                <td>{key}</td>
                <td>{value}</td>
            </tr>
"""

    html += """
        </table>
    </div>

</div>

<h2>Alerts</h2>

<table>
<tr>
<th>IP</th>
<th>Failed Attempts</th>
<th>Threat Level</th>
<th>Threat Intel</th>
<th>Country</th>
<th>MITRE ATT&CK</th>
<th>ML Threat Score</th>
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
<td>{alert["country"]}</td>
<td>{alert["mitre_attack"]}</td>
<td>{alert["ml_threat_score"]}/100</td>
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
<th>Country</th>
<th>MITRE ATT&CK</th>
<th>Anomaly</th>
<th>ML Score</th>
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
<td>{event["country"]}</td>
<td>{event["mitre_attack"]}</td>
<td>{event["anomaly_detected"]}</td>
<td>{event["ml_threat_score"]}/100</td>
</tr>
"""

    html += f"""
</table>

<div class="footer">
Mini SIEM Dashboard V16 | Python Security Monitoring Project | SOC Analytics Dashboard
</div>

<script>
const severityCtx = document.getElementById('severityChart');

new Chart(severityCtx, {{
    type: 'bar',
    data: {{
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{{
            label: 'Severity Count',
            data: [{low_count}, {medium_count}, {high_count}, {critical_count}],
            backgroundColor: ['#22c55e', '#eab308', '#ef4444', '#fb7185']
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{
                labels: {{
                    color: 'white'
                }}
            }}
        }},
        scales: {{
            x: {{
                ticks: {{
                    color: 'white'
                }}
            }},
            y: {{
                ticks: {{
                    color: 'white'
                }}
            }}
        }}
    }}
}});

const loginCtx = document.getElementById('loginChart');

new Chart(loginCtx, {{
    type: 'doughnut',
    data: {{
        labels: ['Success', 'Failed'],
        datasets: [{{
            data: [{success_count}, {failed_count}],
            backgroundColor: ['#22c55e', '#ef4444']
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{
                labels: {{
                    color: 'white'
                }}
            }}
        }}
    }}
}});

const countryCtx = document.getElementById('countryChart');

new Chart(countryCtx, {{
    type: 'bar',
    data: {{
        labels: {json.dumps(countries)},
        datasets: [{{
            label: 'Events by Country',
            data: {json.dumps(country_values)},
            backgroundColor: '#38bdf8'
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{
                labels: {{
                    color: 'white'
                }}
            }}
        }},
        scales: {{
            x: {{
                ticks: {{
                    color: 'white'
                }}
            }},
            y: {{
                ticks: {{
                    color: 'white'
                }}
            }}
        }}
    }}
}});
</script>

</body>
</html>
"""

    with open(HTML_FILE, "w", encoding="utf-8") as html_file:
        html_file.write(html)


def generate_all_reports(summary, events, alerts, heatmap):
    generate_text_report(summary, events, alerts, heatmap)
    generate_json_report(summary, events, alerts, heatmap)
    generate_html_dashboard(summary, events, alerts, heatmap)
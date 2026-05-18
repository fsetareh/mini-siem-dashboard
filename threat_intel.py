THREAT_INTEL = {
    "185.220.101.45": "Known TOR exit node",
    "91.200.12.77": "Known brute-force attacker",
    "45.33.32.156": "Malware command-and-control server"
}


def check_threat_intel(ip):
    return THREAT_INTEL.get(ip, "N/A")
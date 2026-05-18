def parse_log_line(log_line):
    parts = log_line.strip().split(" | ")

    timestamp = parts[0]
    event_type = parts[1]
    user = parts[2].replace("user=", "")
    ip = parts[3].replace("ip=", "")

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": user,
        "ip": ip
    }


def read_logs(log_file):
    with open(log_file, "r", encoding="utf-8") as file:
        return file.readlines()
# ssh module
import re
from collections import defaultdict
from datetime import datetime, timedelta
from subprocess import PIPE, Popen

SSH_UNIT = "sshd"

pattern = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
)


def monitor_ssh():
    process = Popen(
        ["journalctl", "-u", SSH_UNIT, "-f", "-n", "0"],
        stdout=PIPE,
        text=True,
    )

    failed_attempts = defaultdict(list)

    # Stores when the last alert was sent for an IP
    alerted_ips = {}

    for line in process.stdout:
        match = pattern.search(line)

        if not match:
            continue

        event = {
            "event": "failed_login",
            "time": match.group("time"),
            "user": match.group("user"),
            "ip": match.group("ip"),
        }

        ip = event["ip"]

        event_time = datetime.strptime(event["time"], "%H:%M:%S")

        window_start = event_time - timedelta(seconds=60)

        # Add current event
        failed_attempts[ip].append(event_time)

        # Keep only events from the last 60 seconds
        failed_attempts[ip] = [t for t in failed_attempts[ip] if t > window_start]

        # Brute-force detection
        if len(failed_attempts[ip]) >= 5:
            should_alert = False

            # First alert for this IP
            if ip not in alerted_ips:
                should_alert = True

            # Re-alert after 120 seconds
            elif (event_time - alerted_ips[ip]).total_seconds() > 120:
                should_alert = True

            if should_alert:
                print(
                    f"[ALERT] Possible Brute Force | "
                    f"ip={ip} "
                    f"attempts={len(failed_attempts[ip])} "
                    f"window=60s"
                )

                # Store alert timestamp
                alerted_ips[ip] = event_time

        print(
            f"[SSH] Failed Login | "
            f"user={event['user']} "
            f"ip={event['ip']} "
            f"time={event['time']} "
            f"attempts={len(failed_attempts[ip])}"
        )

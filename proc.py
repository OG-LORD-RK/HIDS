import os
import time

WATCHLIST = {
    "ping",
    "nc",
    "ncat",
    "socat",
    "python3",
    "tcpdump",
}


def scan_processes(seen_pids):

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()

            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode()

            ppid = None

            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = line.split()[1]
                        break

            if not ppid or ppid == "0":
                continue

            with open(f"/proc/{ppid}/comm") as f:
                parent_name = f.read().strip()

            # Skip processes we've already examined
            if pid in seen_pids:
                continue

            seen_pids.add(pid)

            score = 0

            event = {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "parent": parent_name,
                "cmdline": cmdline,
                "score": score,
            }

            if event["name"] in WATCHLIST:
                score += 3

            if "/dev/tcp/" in event["cmdline"]:
                score += 5

            event["score"] = score

            if event["score"] >= 3:
                print(
                    f"[PROC] "
                    f"score={event['score']} "
                    f"name={event['name']} "
                    f"parent={event['parent']} "
                    f"pid={event['pid']} "
                    f"cmdline={event['cmdline']}"
                )

        except (
            FileNotFoundError,
            ProcessLookupError,
            PermissionError,
        ):
            pass


def monitor_processes(seen_pids):

    while True:
        scan_processes(seen_pids)

        time.sleep(5)

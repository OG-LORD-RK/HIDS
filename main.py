import threading

import proc
import ssh

seen_pids = set()

ssh_thread = threading.Thread(
    target=ssh.monitor_ssh,
    daemon=True,
)

proc_thread = threading.Thread(
    target=proc.monitor_processes,
    args=(seen_pids,),
    daemon=True,
)

ssh_thread.start()
proc_thread.start()

ssh_thread.join()
proc_thread.join()

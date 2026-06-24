# Linux Host Intrusion Detection System (HIDS)

A lightweight Host Intrusion Detection System written in Python for Linux systems.

The project monitors SSH authentication logs and running processes to detect potentially suspicious activity in real time.

---

## Features

### SSH Monitoring

- Live monitoring of SSH authentication events using "journalctl"
- Failed login detection
- Brute-force attack detection
- Sliding time-window analysis (60 seconds)
- Alert cooldown to prevent alert spam

### Process Monitoring

- Live monitoring of Linux processes via "/proc"
- Process name extraction
- Command-line extraction
- Parent process identification
- Watchlist-based process detection
- Basic risk scoring system
- Duplicate alert suppression

---

### Project Structure

#### main.py
#### ├── ssh.py
#### └── proc.py

##    main.py

Starts monitoring modules and runs them concurrently using Python threads.

##    ssh.py

Monitors SSH logs and detects repeated authentication failures.

##    proc.py

Scans running processes and generates alerts for suspicious activity.

---

## Detection Logic

### SSH Brute Force Detection

#### A brute-force alert is generated when:

- 5 or more failed login attempts
- from the same IP address
- within 60 seconds

### Example:

[ALERT] Possible Brute Force | ip=192.168.1.50 attempts=5 window=60s

---

### Process Detection

#### Processes are converted into structured events:

{
    "pid": pid,
    "ppid": ppid,
    "name": name,
    "parent": parent_name,
    "cmdline": cmdline,
    "score": score
}

#### Current watchlist:

ping
nc
ncat
socat
python3
tcpdump

#### Scoring:

Condition| Score
Process in watchlist| +3
Contains /dev/tcp/| +5

#### Alert threshold:

score >= 3

#### Example:

[PROC] score=3 name=nc parent=lab.sh pid=12345 cmdline=nc -lvnp 4444

---

## Technologies Used

##### - Python
##### - Linux Journald
##### - Regex
##### - Threading
##### - /proc Filesystem

---

## Running

### Start the detector:

##### python main.py

### Generate SSH activity:

##### ssh localhost

### Generate failed logins:

###### ssh fakeuser@localhost

### Generate process activity:

##### ping localhost
##### nc -lvnp 4444
##### python3 -m http.server

---

## Concepts Learned

## Linux

##### - journald
##### - journalctl
##### - SSH logging
##### - /proc filesystem
##### - Process identifiers (PID)
##### - Parent process identifiers (PPID)
##### - Process command lines

## Python

##### - Regular expressions
##### - Dictionaries
##### - Sets
##### - Functions
##### - Modules
##### - Threading
##### - State tracking

## Detection Engineering

##### - Log parsing
##### - Event creation
##### - Sliding windows
##### - Alert suppression
##### - Process scoring
##### - Parent-child process analysis

---

## Future Improvements

##### - Alert logging to file
##### - Configurable watchlists
##### - JSON event output
##### - Email or desktop notifications
##### - Additional monitoring modules
##### - C implementation

---

## Disclaimer

This project is intended for educational and research purposes to learn Linux internals, Python, and intrusion detection concepts.

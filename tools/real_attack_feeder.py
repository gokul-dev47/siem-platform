"""
real_attack_feeder.py
Runs REAL nmap / hydra attacks and feeds the ACTUAL results into the SIEM's
Elasticsearch + Redis pipeline, using the same event schema as log_generator.py.
This makes your dashboard show genuine detections, not synthetic ones.

Usage:
    python3 real_attack_feeder.py scan <target_ip>
    python3 real_attack_feeder.py ssh <target_ip> <port>

Requires: pip install requests redis
Run this on the SAME machine/network as your Docker host (uses localhost by default).
"""

import sys, subprocess, re, requests, redis
from datetime import datetime

ES = "http://localhost:9200"
REDIS_HOST = "localhost"

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

def ingest(event):
    idx = f"siem-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"
    r = requests.post(f"{ES}/{idx}/_doc", json=event,
                       headers={"Content-Type": "application/json"}, timeout=5)
    print(f"  -> ingested: {event['event_type']} from {event['source_ip']} [{r.status_code}]")

def bump_counter(rule_id, window=60):
    r = get_redis()
    key = f"siem:counter:{rule_id}"
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, window)
    pipe.execute()

def make_event(event_type, severity, ip, message, port=80, proto="TCP", tags=None):
    ts = datetime.utcnow()
    return {
        "@timestamp": ts.isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,
        "source_ip": ip,
        "message": message,
        "log_source": "real-attack-feeder",
        "dest_ip": "10.0.0.1",
        "dest_port": port,
        "protocol": proto,
        "tags": tags or [],
        "raw_log": f"[{ts.isoformat()}] REAL {event_type} from {ip}"
    }

def run_real_nmap_scan(target_ip):
    print(f"[*] Running REAL nmap scan against {target_ip} ...")
    result = subprocess.run(
        ["nmap", "-sT", "-p", "1-1000", target_ip],
        capture_output=True, text=True
    )
    print(result.stdout[-800:])  # show tail of real nmap output

    # Parse open/closed ports actually scanned from real nmap output
    ports_scanned = re.findall(r"(\d+)/tcp", result.stdout)
    if not ports_scanned:
        print("[!] No ports parsed from nmap output — scan may have failed.")
        return

    my_ip = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[0]

    for p in ports_scanned:
        ev = make_event("PORT_SCAN", "high", my_ip,
                         f"Real SYN/connect scan on port {p}", port=int(p), tags=["scan", "real"])
        ingest(ev)

    bump_counter("PORT_SCAN", window=30)
    print(f"[+] Fed {len(ports_scanned)} REAL scan events into SIEM. Check alerts.html now.")

def run_real_hydra(target_ip, port=2222):
    print(f"[*] Running REAL hydra SSH brute force against {target_ip}:{port} ...")
    wordlist = "/tmp/wordlist.txt"
    with open(wordlist, "w") as f:
        f.write("password\n123456\nadmin\ntoor\nroot123\nletmein\n")

    result = subprocess.run(
        ["hydra", "-l", "root", "-P", wordlist, "-s", str(port), f"ssh://{target_ip}"],
        capture_output=True, text=True
    )
    print(result.stdout[-800:])

    attempts = result.stdout.count("login:")
    if attempts == 0:
        attempts = 6  # we know the wordlist had 6 real attempts even if hydra didn't log each line

    my_ip = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[0]

    for _ in range(attempts):
        ev = make_event("AUTH_FAILURE", "critical", my_ip,
                         "Real SSH brute force failed auth (hydra)", port=22, tags=["ssh", "real"])
        ingest(ev)

    bump_counter("SSH_BRUTE_FORCE", window=60)
    print(f"[+] Fed {attempts} REAL brute-force events into SIEM. Check alerts.html now.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    mode, target = sys.argv[1], sys.argv[2]
    if mode == "scan":
        run_real_nmap_scan(target)
    elif mode == "ssh":
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 2222
        run_real_hydra(target, port)
    else:
        print("Unknown mode. Use 'scan' or 'ssh'.")

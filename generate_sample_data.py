"""Generate synthetic network traffic CSV with injected anomalies."""

import os
import random
import csv
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NUM_NORMAL_ROWS = 2900
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sample_traffic.csv")

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH", "FTP", "ICMP"]
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(1, 51)]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 101)]
COMMON_PORTS = [80, 443, 22, 53, 8080, 3306, 5432, 25, 110, 143]

COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_sent", "packets_sent", "duration_sec",
]


def _rand_ts(base: datetime, window_seconds: int = 86400) -> datetime:
    """Return a random timestamp within *window_seconds* after *base*."""
    return base + timedelta(seconds=random.randint(0, window_seconds))


def _normal_row(base: datetime) -> dict:
    ts = _rand_ts(base)
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(EXTERNAL_IPS),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(COMMON_PORTS),
        "protocol": random.choice(PROTOCOLS),
        "bytes_sent": random.randint(40, 15_000),
        "packets_sent": random.randint(1, 80),
        "duration_sec": round(random.uniform(0.01, 30.0), 2),
    }


# ---------------------------------------------------------------------------
# Anomaly generators
# ---------------------------------------------------------------------------

def _port_scan_rows(base: datetime, count: int = 40) -> list[dict]:
    """One src_ip scanning many dst_ports on a single target in a short burst."""
    attacker = "10.0.1.99"
    target = "203.0.113.50"
    scan_start = base + timedelta(hours=6)  # cluster at hour-6
    rows = []
    for i in range(count):
        ts = scan_start + timedelta(seconds=i * 0.3)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker,
            "dst_ip": target,
            "src_port": random.randint(40000, 65535),
            "dst_port": 1 + i,  # sequential port scan
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 80),      # tiny SYN packets
            "packets_sent": 1,
            "duration_sec": round(random.uniform(0.001, 0.05), 4),
        })
    return rows


def _large_transfer_rows(base: datetime, count: int = 3) -> list[dict]:
    """Abnormally large data-transfer flow(s)."""
    exfil_start = base + timedelta(hours=14)
    rows = []
    for i in range(count):
        ts = exfil_start + timedelta(minutes=i * 2)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "10.0.1.42",
            "dst_ip": "203.0.113.77",
            "src_port": random.randint(40000, 65535),
            "dst_port": 443,
            "protocol": "HTTPS",
            "bytes_sent": random.randint(8_000_000, 15_000_000),  # 8–15 MB
            "packets_sent": random.randint(5000, 12000),
            "duration_sec": round(random.uniform(60, 300), 2),
        })
    return rows


def _ddos_burst_rows(base: datetime, count: int = 50) -> list[dict]:
    """Many different src_ips flood one dst_ip in a short window."""
    target = "10.0.1.10"
    burst_start = base + timedelta(hours=20)
    rows = []
    for i in range(count):
        ts = burst_start + timedelta(seconds=random.uniform(0, 10))
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "dst_ip": target,
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": random.randint(500, 3000),
            "packets_sent": random.randint(10, 100),
            "duration_sec": round(random.uniform(0.01, 1.0), 3),
        })
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate(seed: int = 42) -> str:
    """Generate sample_traffic.csv and return its path."""
    random.seed(seed)
    base = datetime(2025, 7, 1, 0, 0, 0)

    rows = [_normal_row(base) for _ in range(NUM_NORMAL_ROWS)]
    rows += _port_scan_rows(base)
    rows += _large_transfer_rows(base)
    rows += _ddos_burst_rows(base)

    # Sort by timestamp so it looks realistic
    rows.sort(key=lambda r: r["timestamp"])

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote {len(rows)} rows -> {OUTPUT_FILE}")
    return OUTPUT_FILE


if __name__ == "__main__":
    generate()

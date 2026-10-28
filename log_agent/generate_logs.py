"""Deterministic synthetic security log generator for cybersecurity log analysis."""

import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple


def generate_logs(
    output_csv_path: str = "data/logs.csv",
    output_gt_path: str = "data/ground_truth.json",
    seed: int = 42,
    target_row_count: int = 6500,
) -> Tuple[int, str, str]:
    """Generate realistic security logs with 5 specific scenarios and normal background traffic.

    Args:
        output_csv_path: Path where logs CSV will be written.
        output_gt_path: Path where ground truth JSON will be written.
        seed: Random seed for deterministic generation.
        target_row_count: Approximate number of rows to generate.

    Returns:
        Tuple of (total_rows_generated, output_csv_path, output_gt_path)
    """
    random.seed(seed)

    base_time = datetime(2026, 10, 15, 0, 0, 0, tzinfo=timezone.utc)
    hosts = [
        "auth-srv-01.corp.internal",
        "auth-srv-02.corp.internal",
        "vpn-gw-01.corp.internal",
    ]

    # Standard normal corporate users (30 users)
    normal_users = [
        f"user{i:02d}.corp" for i in range(1, 29)
    ]
    # Designated users
    admin_user = "admin.carol"
    benign_noisy_user = "charlie.brown"
    brute_force_victim = "victim.alice"
    cred_stuffing_victim = "executive.dan"
    all_users = normal_users + [admin_user, benign_noisy_user, brute_force_victim, cred_stuffing_victim]

    # Internal IP mappings for normal users (predictable historical baseline)
    user_internal_ips = {}
    for idx, u in enumerate(all_users):
        user_internal_ips[u] = f"10.0.1.{10 + idx}"

    rows: List[Dict[str, str]] = []

    # -------------------------------------------------------------
    # 1. Normal Background Traffic (~5,800 events across 7 days)
    # -------------------------------------------------------------
    # Each day has business hours (08:00 - 18:00 UTC) with peak logins
    for day in range(7):
        current_day_date = base_time + timedelta(days=day)
        # Weekday vs weekend activity
        is_weekend = (day >= 5)
        day_events = 400 if is_weekend else 900

        for _ in range(day_events):
            if is_weekend:
                # Fewer logins, spread across day
                hour = random.randint(9, 17)
            else:
                # 85% business hours (08:00 - 18:00), 15% early evening (18:00 - 20:00)
                if random.random() < 0.85:
                    hour = random.randint(8, 17)
                else:
                    hour = random.randint(18, 19)

            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            event_time = current_day_date.replace(hour=hour, minute=minute, second=second)
            iso_time = event_time.isoformat()

            user = random.choice(all_users)
            # Most logins from user's standard internal IP, occasionally another internal IP
            if random.random() < 0.95:
                ip = user_internal_ips[user]
            else:
                ip = f"10.0.2.{random.randint(2, 250)}"

            host = random.choice(hosts)

            # Normal behavior: mostly success, occasional 1 typo failed login before success
            rand_val = random.random()
            if rand_val < 0.08:
                # Typo: failed login followed by success within 30 seconds
                rows.append({
                    "timestamp": iso_time,
                    "source_ip": ip,
                    "username": user,
                    "event_type": "login_failed",
                    "status": "failure",
                    "host": host,
                })
                success_time = (event_time + timedelta(seconds=random.randint(5, 30))).isoformat()
                rows.append({
                    "timestamp": success_time,
                    "source_ip": ip,
                    "username": user,
                    "event_type": "login_success",
                    "status": "success",
                    "host": host,
                })
            elif rand_val < 0.70:
                rows.append({
                    "timestamp": iso_time,
                    "source_ip": ip,
                    "username": user,
                    "event_type": "login_success",
                    "status": "success",
                    "host": host,
                })
            else:
                rows.append({
                    "timestamp": iso_time,
                    "source_ip": ip,
                    "username": user,
                    "event_type": "logout",
                    "status": "success",
                    "host": host,
                })

    # -------------------------------------------------------------
    # Scenario 1: Brute Force
    # - 1 external IP (198.51.100.45)
    # - ~50 failed login attempts against one account within a few minutes
    # - 1 successful login follows the failures
    # - Day 2: 2026-10-17 14:10:00Z to 14:14:00Z
    # -------------------------------------------------------------
    s1_ip = "198.51.100.45"
    s1_user = brute_force_victim
    s1_start = base_time + timedelta(days=2, hours=14, minutes=10, seconds=0)
    for i in range(52):
        t = s1_start + timedelta(seconds=i * 4 + random.randint(0, 2))
        rows.append({
            "timestamp": t.isoformat(),
            "source_ip": s1_ip,
            "username": s1_user,
            "event_type": "login_failed",
            "status": "failure",
            "host": "auth-srv-01.corp.internal",
        })
    s1_success_time = s1_start + timedelta(seconds=52 * 4 + 15)
    rows.append({
        "timestamp": s1_success_time.isoformat(),
        "source_ip": s1_ip,
        "username": s1_user,
        "event_type": "login_success",
        "status": "success",
        "host": "auth-srv-01.corp.internal",
    })

    # -------------------------------------------------------------
    # Scenario 2: Password Spraying
    # - 1 external IP (203.0.113.88)
    # - Attempts against ~25 distinct usernames
    # - 1 or 2 failed attempts per user
    # - NO successful login
    # - Day 3: 2026-10-18 10:00:00Z to 10:20:00Z
    # -------------------------------------------------------------
    s2_ip = "203.0.113.88"
    spray_users = [f"spray_target_{i:02d}" for i in range(1, 26)]
    s2_start = base_time + timedelta(days=3, hours=10, minutes=0, seconds=0)
    s2_counter = 0
    for spray_u in spray_users:
        attempts = random.choice([1, 2])
        for _ in range(attempts):
            t = s2_start + timedelta(seconds=s2_counter * 25 + random.randint(1, 5))
            rows.append({
                "timestamp": t.isoformat(),
                "source_ip": s2_ip,
                "username": spray_u,
                "event_type": "login_failed",
                "status": "failure",
                "host": "auth-srv-02.corp.internal",
            })
            s2_counter += 1

    # -------------------------------------------------------------
    # Scenario 3: Off-Hours Administrator Login
    # - admin.carol historical activity is strictly business hours from 10.0.1.32
    # - At 03:15 AM on Day 4 (2026-10-19), successful login from new external IP 198.51.100.201
    # -------------------------------------------------------------
    s3_ip = "198.51.100.201"
    s3_user = admin_user
    s3_time = base_time + timedelta(days=4, hours=3, minutes=15, seconds=22)
    rows.append({
        "timestamp": s3_time.isoformat(),
        "source_ip": s3_ip,
        "username": s3_user,
        "event_type": "login_success",
        "status": "success",
        "host": "auth-srv-01.corp.internal",
    })

    # -------------------------------------------------------------
    # Scenario 4: Credential Stuffing / Distributed Account Abuse
    # - executive.dan successfully authenticates from 9 distinct external IPs within 35 minutes
    # - Day 4: 2026-10-19 16:00:00Z to 16:35:00Z
    # -------------------------------------------------------------
    s4_user = cred_stuffing_victim
    s4_ips = [f"198.51.100.{11 + i}" for i in range(9)]
    s4_start = base_time + timedelta(days=4, hours=16, minutes=0, seconds=0)
    for idx, ext_ip in enumerate(s4_ips):
        t = s4_start + timedelta(minutes=idx * 3 + random.randint(0, 1), seconds=random.randint(5, 50))
        rows.append({
            "timestamp": t.isoformat(),
            "source_ip": ext_ip,
            "username": s4_user,
            "event_type": "login_success",
            "status": "success",
            "host": "vpn-gw-01.corp.internal",
        })

    # -------------------------------------------------------------
    # Scenario 5: Benign Noisy User (False Positive test)
    # - charlie.brown experiences 12 failed logins followed by 1 successful login
    # - All attempts originate from user's usual IP (10.0.1.33)
    # - Day 5: 2026-10-20 09:30:00Z to 09:38:00Z
    # -------------------------------------------------------------
    s5_user = benign_noisy_user
    s5_ip = user_internal_ips[s5_user]  # Usual internal IP
    s5_start = base_time + timedelta(days=5, hours=9, minutes=30, seconds=0)
    for i in range(12):
        t = s5_start + timedelta(seconds=i * 35 + random.randint(2, 10))
        rows.append({
            "timestamp": t.isoformat(),
            "source_ip": s5_ip,
            "username": s5_user,
            "event_type": "login_failed",
            "status": "failure",
            "host": "auth-srv-01.corp.internal",
        })
    s5_success_time = s5_start + timedelta(seconds=12 * 35 + 20)
    rows.append({
        "timestamp": s5_success_time.isoformat(),
        "source_ip": s5_ip,
        "username": s5_user,
        "event_type": "login_success",
        "status": "success",
        "host": "auth-srv-01.corp.internal",
    })

    # -------------------------------------------------------------
    # Sort chronologically by timestamp
    # -------------------------------------------------------------
    rows.sort(key=lambda r: r["timestamp"])

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(output_csv_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(output_gt_path)), exist_ok=True)

    # Write CSV
    fieldnames = ["timestamp", "source_ip", "username", "event_type", "status", "host"]
    with open(output_csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Ground truth data
    ground_truth = {
        "dataset_metadata": {
            "total_rows": len(rows),
            "seed": seed,
            "generated_at": "2026-10-22T00:00:00Z",
            "date_range": [rows[0]["timestamp"], rows[-1]["timestamp"]],
        },
        "scenarios": [
            {
                "name": "scenario_1_brute_force",
                "description": "Brute force attack of ~50 failed logins from external IP followed by successful login",
                "involved_ips": [s1_ip],
                "involved_usernames": [s1_user],
                "time_window": [s1_start.isoformat(), s1_success_time.isoformat()],
                "is_malicious": True,
                "expected_attack_type": "Brute Force",
                "expected_risk_min": "High",
            },
            {
                "name": "scenario_2_password_spraying",
                "description": "Password spraying against 25 distinct accounts from single external IP with no successes",
                "involved_ips": [s2_ip],
                "involved_usernames": spray_users,
                "time_window": [
                    s2_start.isoformat(),
                    (s2_start + timedelta(seconds=s2_counter * 25 + 10)).isoformat(),
                ],
                "is_malicious": True,
                "expected_attack_type": "Password Spraying",
                "expected_risk_min": "High",
            },
            {
                "name": "scenario_3_off_hours_admin",
                "description": "Off-hours administrator login at 03:15 AM from previously unseen external IP",
                "involved_ips": [s3_ip],
                "involved_usernames": [s3_user],
                "time_window": [s3_time.isoformat(), s3_time.isoformat()],
                "is_malicious": True,
                "expected_attack_type": "Off-Hours Admin Login",
                "expected_risk_min": "Medium",
            },
            {
                "name": "scenario_4_credential_stuffing_distributed",
                "description": "Single account successfully logged into from 9 distinct external IPs within 35 minutes",
                "involved_ips": s4_ips,
                "involved_usernames": [s4_user],
                "time_window": [
                    s4_start.isoformat(),
                    (s4_start + timedelta(minutes=27, seconds=50)).isoformat(),
                ],
                "is_malicious": True,
                "expected_attack_type": "Credential Stuffing",
                "expected_risk_min": "High",
            },
            {
                "name": "scenario_5_benign_noisy_user",
                "description": "Benign user forgotten password with 12 failed logins followed by success from usual IP",
                "involved_ips": [s5_ip],
                "involved_usernames": [s5_user],
                "time_window": [s5_start.isoformat(), s5_success_time.isoformat()],
                "is_malicious": False,
                "expected_attack_type": "Benign Noise",
                "expected_risk_max": "Low",
            },
        ],
    }

    with open(output_gt_path, mode="w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    return len(rows), output_csv_path, output_gt_path


if __name__ == "__main__":
    # Support running from project root or log_agent directory
    script_dir = Path(__file__).resolve().parent
    csv_out = str(script_dir / "data" / "logs.csv")
    gt_out = str(script_dir / "data" / "ground_truth.json")

    total, c_path, g_path = generate_logs(csv_out, gt_out)
    print(f"Generated {total} log entries.")
    print(f"Logs written to: {c_path}")
    print(f"Ground truth written to: {g_path}")

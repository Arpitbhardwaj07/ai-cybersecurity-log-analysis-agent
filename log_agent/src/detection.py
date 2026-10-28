"""Deterministic rule-based detection engine for cybersecurity security logs."""

import ipaddress
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from src.schemas import Finding

# -------------------------------------------------------------
# Configurable Detection Thresholds
# -------------------------------------------------------------
BURST_COUNT_THRESHOLD = 10
BURST_WINDOW_MINUTES = 10

SUCCESS_AFTER_BURST_MINUTES = 15

SPRAYING_DISTINCT_USERS = 10
SPRAYING_WINDOW_MINUTES = 30

OFF_HOURS_START_HOUR = 20  # 8 PM
OFF_HOURS_END_HOUR = 7     # 7 AM
BUSINESS_HOURS_RATIO_MIN = 0.75
MIN_HISTORICAL_LOGINS = 5

MULTI_IP_THRESHOLD = 5
MULTI_IP_WINDOW_HOURS = 1


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_ip_private(ip_str: str) -> bool:
    """Check if an IP address string is an internal private RFC1918/loopback address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return any(ip_obj in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def validate_logs(df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
    """Validate DataFrame against required schema, valid timestamps, valid event types, and IP addresses.

    Raises:
        ValueError: if required columns are missing or data is malformed.
    """
    required_cols = {"timestamp", "source_ip", "username", "event_type", "status", "host"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Uploaded CSV is missing required columns: {sorted(list(missing))}")

    if df.empty:
        raise ValueError("Uploaded CSV is empty")

    # Check for nulls in required columns
    for col in required_cols:
        null_count = df[col].isna().sum()
        if null_count > 0:
            raise ValueError(f"Column '{col}' contains {null_count} missing or empty values.")

    # Validate timestamps
    try:
        parsed_ts = pd.to_datetime(df["timestamp"], format="ISO8601")
        if parsed_ts.isna().any():
            raise ValueError("Some timestamps could not be parsed as valid ISO8601 strings.")
    except Exception as e:
        raise ValueError(f"Invalid timestamp format detected: {str(e)}")

    # Validate event types
    valid_events = {"login_failed", "login_success", "logout"}
    actual_events = set(df["event_type"].unique())
    invalid_events = actual_events - valid_events
    if invalid_events:
        raise ValueError(f"Invalid event_type found: {invalid_events}. Expected only {valid_events}")

    # Validate IP addresses
    sample_ips = df["source_ip"].unique()
    for ip in sample_ips:
        try:
            ipaddress.ip_address(str(ip).strip())
        except ValueError:
            raise ValueError(f"Malformed or invalid IP address found in logs: '{ip}'")

    return True, None


def detect_findings(df: pd.DataFrame) -> List[Finding]:
    """Execute deterministic detection rules on logs and return deduplicated candidate findings."""
    validate_logs(df)

    work_df = df.copy()
    work_df["parsed_timestamp"] = pd.to_datetime(work_df["timestamp"], format="ISO8601")
    work_df = work_df.sort_values("parsed_timestamp").reset_index(drop=True)

    findings: List[Finding] = []

    # -------------------------------------------------------------
    # 1 & 2. Failed Login Burst & Failed-Then-Success Rule
    # -------------------------------------------------------------
    # Group failures by IP
    failures_df = work_df[work_df["event_type"] == "login_failed"].copy()
    success_df = work_df[work_df["event_type"] == "login_success"].copy()

    for ip, ip_failures in failures_df.groupby("source_ip"):
        ip_failures = ip_failures.sort_values("parsed_timestamp")
        n_fails = len(ip_failures)
        if n_fails < BURST_COUNT_THRESHOLD:
            continue

        # Detect burst windows using two-pointer / rolling window
        times = ip_failures["parsed_timestamp"].tolist()
        users = ip_failures["username"].tolist()
        burst_ranges = []
        i = 0
        while i < n_fails:
            # find all failures within BURST_WINDOW_MINUTES from times[i]
            window_end = times[i] + timedelta(minutes=BURST_WINDOW_MINUTES)
            j = i
            while j < n_fails and times[j] <= window_end:
                j += 1
            count = j - i
            if count >= BURST_COUNT_THRESHOLD:
                # Expand cluster to all consecutive failures with gap < 10 mins
                end_idx = j - 1
                while end_idx + 1 < n_fails and (times[end_idx + 1] - times[end_idx]) <= timedelta(minutes=BURST_WINDOW_MINUTES):
                    end_idx += 1
                burst_ranges.append((i, end_idx))
                i = end_idx + 1
            else:
                i += 1

        for start_idx, end_idx in burst_ranges:
            burst_start_t = times[start_idx]
            burst_end_t = times[end_idx]
            burst_fails_count = end_idx - start_idx + 1
            involved_users = list(set(users[start_idx:end_idx + 1]))

            # Check if there is a success from the same IP within SUCCESS_AFTER_BURST_MINUTES after the burst
            success_window_end = burst_end_t + timedelta(minutes=SUCCESS_AFTER_BURST_MINUTES)
            ip_successes = success_df[
                (success_df["source_ip"] == ip)
                & (success_df["parsed_timestamp"] >= burst_end_t)
                & (success_df["parsed_timestamp"] <= success_window_end)
            ]

            is_private = is_ip_private(str(ip))

            if not ip_successes.empty:
                # Failed then success detected!
                first_succ = ip_successes.iloc[0]
                succ_user = first_succ["username"]
                succ_time = first_succ["parsed_timestamp"]

                # If from internal IP with single user, lower severity so benign noisy user is not over-escalated
                if is_private:
                    sev = 60.0
                    rule_name = "failed_then_success"
                    desc = (
                        f"Failed login burst ({burst_fails_count} failures) followed by successful login "
                        f"for user '{succ_user}' from internal IP {ip}."
                    )
                else:
                    sev = 90.0
                    rule_name = "failed_then_success"
                    desc = (
                        f"Suspicious failed login burst ({burst_fails_count} failures) followed by successful login "
                        f"for user '{succ_user}' from external IP {ip}."
                    )

                findings.append(
                    Finding(
                        id=f"find_{uuid.uuid4().hex[:8]}",
                        rule=rule_name,
                        severity_score=sev,
                        ip=str(ip),
                        username=str(succ_user),
                        start_time=burst_start_t.isoformat(),
                        end_time=succ_time.isoformat(),
                        description=desc,
                        metadata={
                            "failed_login_count": burst_fails_count,
                            "success_occurred": True,
                            "success_timestamp": succ_time.isoformat(),
                            "is_private_ip": is_private,
                            "targeted_users": involved_users,
                        },
                    )
                )
            else:
                # Standalone burst without success (if not covered by password spraying)
                # If spraying (many distinct users), spraying rule will capture it with higher specificity
                if len(involved_users) < SPRAYING_DISTINCT_USERS:
                    sev = 50.0 if is_private else 70.0
                    findings.append(
                        Finding(
                            id=f"find_{uuid.uuid4().hex[:8]}",
                            rule="failed_login_burst",
                            severity_score=sev,
                            ip=str(ip),
                            username=involved_users[0] if len(involved_users) == 1 else None,
                            start_time=burst_start_t.isoformat(),
                            end_time=burst_end_t.isoformat(),
                            description=f"Burst of {burst_fails_count} failed logins from {ip}.",
                            metadata={
                                "failed_login_count": burst_fails_count,
                                "success_occurred": False,
                                "is_private_ip": is_private,
                                "targeted_users": involved_users,
                            },
                        )
                    )

    # -------------------------------------------------------------
    # 3. Password Spraying Rule
    # -------------------------------------------------------------
    for ip, ip_fails in failures_df.groupby("source_ip"):
        ip_fails = ip_fails.sort_values("parsed_timestamp")
        unique_users_all = ip_fails["username"].nunique()
        if unique_users_all < SPRAYING_DISTINCT_USERS:
            continue

        times = ip_fails["parsed_timestamp"].tolist()
        users = ip_fails["username"].tolist()
        n = len(times)

        # Sliding window for 30 minutes
        i = 0
        while i < n:
            window_end = times[i] + timedelta(minutes=SPRAYING_WINDOW_MINUTES)
            j = i
            seen_users = set()
            while j < n and times[j] <= window_end:
                seen_users.add(users[j])
                j += 1

            if len(seen_users) >= SPRAYING_DISTINCT_USERS:
                start_t = times[i]
                end_t = times[j - 1]
                is_private = is_ip_private(str(ip))
                sev = 65.0 if is_private else 85.0

                findings.append(
                    Finding(
                        id=f"find_{uuid.uuid4().hex[:8]}",
                        rule="password_spraying",
                        severity_score=sev,
                        ip=str(ip),
                        username=None,
                        start_time=start_t.isoformat(),
                        end_time=end_t.isoformat(),
                        description=(
                            f"Password spraying detected from IP {ip} targeting "
                            f"{len(seen_users)} distinct accounts within 30 minutes."
                        ),
                        metadata={
                            "distinct_usernames_count": len(seen_users),
                            "distinct_usernames": sorted(list(seen_users)),
                            "is_private_ip": is_private,
                            "attempt_count": j - i,
                        },
                    )
                )
                # Advance past this cluster
                i = j
            else:
                i += 1

    # -------------------------------------------------------------
    # 4. Off-Hours Administrator / User Login Rule
    # -------------------------------------------------------------
    # Compute business hours baseline per user across all logins
    user_successes = work_df[work_df["event_type"] == "login_success"]
    user_baselines = {}
    for user, u_df in user_successes.groupby("username"):
        total_logins = len(u_df)
        if total_logins < MIN_HISTORICAL_LOGINS:
            continue
        # Check hour
        hours = u_df["parsed_timestamp"].dt.hour
        biz_logins = ((hours >= OFF_HOURS_END_HOUR) & (hours < OFF_HOURS_START_HOUR)).sum()
        ratio = biz_logins / total_logins
        user_baselines[user] = {
            "business_ratio": ratio,
            "total_logins": total_logins,
            "historical_ips": set(u_df["source_ip"].unique()),
        }

    for idx, row in user_successes.iterrows():
        u = row["username"]
        if u not in user_baselines:
            continue
        baseline = user_baselines[u]
        if baseline["business_ratio"] < BUSINESS_HOURS_RATIO_MIN:
            continue

        ts = row["parsed_timestamp"]
        hour = ts.hour
        # Off-hours: outside 07:00-20:00 (hour >= 20 or hour < 7)
        if hour >= OFF_HOURS_START_HOUR or hour < OFF_HOURS_END_HOUR:
            ip = str(row["source_ip"])
            is_private = is_ip_private(ip)
            # Check historical IPs for this user prior to this timestamp
            prior_ips = user_successes[
                (user_successes["username"] == u)
                & (user_successes["parsed_timestamp"] < ts)
            ]["source_ip"].unique()

            is_new_ip = ip not in prior_ips
            if not is_new_ip and is_private:
                # Routine internal login, not suspicious
                continue

            sev = 80.0 if (is_new_ip and not is_private) else 65.0

            findings.append(
                Finding(
                    id=f"find_{uuid.uuid4().hex[:8]}",
                    rule="off_hours_login",
                    severity_score=sev,
                    ip=ip,
                    username=str(u),
                    start_time=ts.isoformat(),
                    end_time=ts.isoformat(),
                    description=(
                        f"Off-hours successful login by '{u}' at {ts.strftime('%H:%M:%S UTC')} "
                        f"from IP {ip} (new IP: {is_new_ip}, private: {is_private})."
                    ),
                    metadata={
                        "hour": hour,
                        "is_new_ip": is_new_ip,
                        "is_private_ip": is_private,
                        "business_hours_ratio": baseline["business_ratio"],
                    },
                )
            )

    # -------------------------------------------------------------
    # 5. Multi-IP Account Rule (Distributed / Credential Stuffing)
    # -------------------------------------------------------------
    for user, u_succ in user_successes.groupby("username"):
        u_succ = u_succ.sort_values("parsed_timestamp")
        n_succ = len(u_succ)
        if n_succ < MULTI_IP_THRESHOLD:
            continue

        times = u_succ["parsed_timestamp"].tolist()
        ips = u_succ["source_ip"].tolist()

        i = 0
        while i < n_succ:
            window_end = times[i] + timedelta(hours=MULTI_IP_WINDOW_HOURS)
            j = i
            seen_ips = set()
            while j < n_succ and times[j] <= window_end:
                seen_ips.add(ips[j])
                j += 1

            if len(seen_ips) >= MULTI_IP_THRESHOLD:
                start_t = times[i]
                end_t = times[j - 1]
                ext_count = sum(1 for ip in seen_ips if not is_ip_private(str(ip)))
                sev = 90.0 if ext_count >= 5 else 75.0

                findings.append(
                    Finding(
                        id=f"find_{uuid.uuid4().hex[:8]}",
                        rule="multi_ip_account",
                        severity_score=sev,
                        ip=list(seen_ips)[0] if len(seen_ips) == 1 else None,
                        username=str(user),
                        start_time=start_t.isoformat(),
                        end_time=end_t.isoformat(),
                        description=(
                            f"Account '{user}' successfully authenticated from {len(seen_ips)} "
                            f"distinct IP addresses within {MULTI_IP_WINDOW_HOURS} hour."
                        ),
                        metadata={
                            "distinct_ips_count": len(seen_ips),
                            "distinct_ips": sorted(list(seen_ips)),
                            "external_ips_count": ext_count,
                        },
                    )
                )
                i = j
            else:
                i += 1

    # -------------------------------------------------------------
    # Deduplication & Merging
    # -------------------------------------------------------------
    deduped = deduplicate_findings(findings)
    # Sort findings by severity score descending
    deduped.sort(key=lambda f: f.severity_score, reverse=True)
    return deduped


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Merge overlapping findings for the same entity and time sequence.

    For example, if both 'failed_login_burst' and 'failed_then_success' trigger
    for the same IP and overlapping time window, merge into 'failed_then_success'
    retaining the higher severity score and most informative rule.
    """
    if not findings:
        return []

    # Sort by start_time
    sorted_findings = sorted(findings, key=lambda f: f.start_time)
    merged: List[Finding] = []

    for f in sorted_findings:
        if not merged:
            merged.append(f)
            continue

        prev = merged[-1]
        # Check if they share the same IP or username and have overlapping/adjacent time windows
        same_ip = (f.ip and prev.ip and f.ip == prev.ip)
        same_user = (f.username and prev.username and f.username == prev.username)

        # Check time overlap (within 15 minutes)
        t_prev_end = pd.to_datetime(prev.end_time)
        t_f_start = pd.to_datetime(f.start_time)
        time_close = abs((t_f_start - t_prev_end).total_seconds()) <= 900 or t_f_start <= t_prev_end

        should_merge = False
        if same_ip and time_close:
            # Overlapping IP activity: e.g. burst + failed_then_success, or multiple spraying windows
            if (prev.rule in ["failed_login_burst", "failed_then_success"] and f.rule in ["failed_login_burst", "failed_then_success"]):
                should_merge = True
            elif prev.rule == "password_spraying" and f.rule == "password_spraying":
                should_merge = True

        if same_user and time_close and (prev.rule == f.rule):
            should_merge = True

        if should_merge:
            # Keep the more severe finding and merge metadata
            best_rule = "failed_then_success" if ("failed_then_success" in [prev.rule, f.rule]) else (
                f.rule if f.severity_score >= prev.severity_score else prev.rule
            )
            merged_sev = max(prev.severity_score, f.severity_score)
            earliest_start = min(prev.start_time, f.start_time)
            latest_end = max(prev.end_time, f.end_time)
            merged_desc = f.description if f.severity_score >= prev.severity_score else prev.description

            combined_metadata = {**prev.metadata, **f.metadata}

            merged[-1] = Finding(
                id=prev.id,
                rule=best_rule,
                severity_score=merged_sev,
                ip=f.ip or prev.ip,
                username=f.username or prev.username,
                start_time=earliest_start,
                end_time=latest_end,
                description=merged_desc,
                metadata=combined_metadata,
            )
        else:
            merged.append(f)

    return merged

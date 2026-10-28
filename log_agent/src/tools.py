"""Deterministic investigation tools for querying and analyzing security logs."""

import ipaddress
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import pandas as pd
from langchain_core.tools import tool

# Module-level DataFrame store
_CURRENT_LOGS_DF: Optional[pd.DataFrame] = None

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
LOCAL_BLOCKLIST: Dict[str, str] = {
    "198.51.100.45": "Observed in distributed SSH/RDP brute-force campaigns",
    "203.0.113.88": "Known password spraying botnet node",
    "198.51.100.201": "Suspicious external IP / Tor exit relay",
    "198.51.100.11": "Known credential stuffing proxy infrastructure",
    "198.51.100.12": "Known credential stuffing proxy infrastructure",
    "198.51.100.13": "Known credential stuffing proxy infrastructure",
}


def load_logs(source: Union[str, pd.DataFrame]) -> None:
    """Safely load logs into module-level memory for tools to query."""
    global _CURRENT_LOGS_DF
    if isinstance(source, pd.DataFrame):
        df = source.copy()
    else:
        df = pd.read_csv(source)

    if "timestamp" in df.columns:
        df["parsed_timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
        df = df.sort_values("parsed_timestamp").reset_index(drop=True)

    _CURRENT_LOGS_DF = df


def get_loaded_logs() -> pd.DataFrame:
    """Retrieve the currently loaded logs DataFrame or an empty DataFrame."""
    global _CURRENT_LOGS_DF
    if _CURRENT_LOGS_DF is None:
        return pd.DataFrame(
            columns=["timestamp", "source_ip", "username", "event_type", "status", "host", "parsed_timestamp"]
        )
    return _CURRENT_LOGS_DF


def _validate_ip(ip_str: Optional[str]) -> Optional[str]:
    """Validate IP string, returns None if valid or error message if invalid."""
    if not ip_str:
        return "IP address cannot be empty."
    try:
        ipaddress.ip_address(str(ip_str).strip())
        return None
    except ValueError:
        return f"Invalid IP address format: '{ip_str}'"


def get_failed_logins(
    ip: Optional[str] = None,
    user: Optional[str] = None,
    window_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """Query failed logins filtered by IP and/or username.

    Args:
        ip: Optional IP address to filter by.
        user: Optional username to filter by.
        window_minutes: Optional time window in minutes to inspect relative to latest event.

    Returns:
        Compact summary dictionary with failure counts, affected accounts, and up to 10 sample events.
    """
    if not ip and not user:
        return {"error": "Either 'ip' or 'user' must be provided.", "status": "failed"}

    if ip:
        err = _validate_ip(ip)
        if err:
            return {"error": err, "status": "failed"}

    df = get_loaded_logs()
    if df.empty:
        return {"error": "No logs currently loaded.", "status": "failed"}

    query = df["event_type"] == "login_failed"
    if ip:
        query = query & (df["source_ip"] == ip.strip())
    if user:
        query = query & (df["username"] == user.strip())

    filtered = df[query].copy()

    if window_minutes and not filtered.empty:
        max_time = filtered["parsed_timestamp"].max()
        min_time = max_time - timedelta(minutes=window_minutes)
        filtered = filtered[filtered["parsed_timestamp"] >= min_time]

    total_failures = len(filtered)
    if total_failures == 0:
        return {
            "status": "success",
            "total_failed_logins": 0,
            "unique_users_targeted": [],
            "unique_ips": [],
            "sample_events": [],
            "message": "No failed logins found matching criteria.",
        }

    first_time = filtered["parsed_timestamp"].min().isoformat()
    last_time = filtered["parsed_timestamp"].max().isoformat()
    unique_users = sorted(filtered["username"].dropna().unique().tolist())
    unique_ips = sorted(filtered["source_ip"].dropna().unique().tolist())

    sample_events = (
        filtered[["timestamp", "source_ip", "username", "status", "host"]]
        .head(10)
        .to_dict(orient="records")
    )

    return {
        "status": "success",
        "total_failed_logins": total_failures,
        "unique_users_count": len(unique_users),
        "unique_users_targeted": unique_users[:15],
        "unique_ips_count": len(unique_ips),
        "unique_ips": unique_ips[:10],
        "first_failure": first_time,
        "last_failure": last_time,
        "sample_events": sample_events,
    }


def get_activity_for_ip(ip: str) -> Dict[str, Any]:
    """Get overall historical activity summary for a given IP address.

    Args:
        ip: IP address to query.

    Returns:
        Compact dictionary of event counts, unique usernames, hosts, and sample events (max 10).
    """
    err = _validate_ip(ip)
    if err:
        return {"error": err, "status": "failed"}

    df = get_loaded_logs()
    if df.empty:
        return {"error": "No logs currently loaded.", "status": "failed"}

    ip_clean = ip.strip()
    filtered = df[df["source_ip"] == ip_clean].copy()

    is_private = is_ip_private(ip_clean)

    total_events = len(filtered)
    if total_events == 0:
        return {
            "status": "success",
            "ip": ip_clean,
            "is_private": is_private,
            "total_events": 0,
            "event_breakdown": {},
            "targeted_users": [],
            "sample_events": [],
            "message": f"No activity recorded for IP {ip_clean}.",
        }

    breakdown = filtered["event_type"].value_counts().to_dict()
    users = sorted(filtered["username"].dropna().unique().tolist())
    hosts = sorted(filtered["host"].dropna().unique().tolist())
    first_seen = filtered["parsed_timestamp"].min().isoformat()
    last_seen = filtered["parsed_timestamp"].max().isoformat()

    sample_events = (
        filtered[["timestamp", "source_ip", "username", "event_type", "status", "host"]]
        .head(10)
        .to_dict(orient="records")
    )

    return {
        "status": "success",
        "ip": ip_clean,
        "is_private": is_private,
        "total_events": total_events,
        "event_breakdown": breakdown,
        "unique_users_count": len(users),
        "targeted_users": users[:10],
        "hosts_targeted": hosts,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sample_events": sample_events,
    }


def get_activity_for_user(user: str) -> Dict[str, Any]:
    """Get overall activity and historical baseline for a given username.

    Args:
        user: Username to query.

    Returns:
        Compact dictionary with total events, distinct IPs, private vs external IPs, and sample events.
    """
    if not user or not str(user).strip():
        return {"error": "Username cannot be empty.", "status": "failed"}

    df = get_loaded_logs()
    if df.empty:
        return {"error": "No logs currently loaded.", "status": "failed"}

    user_clean = str(user).strip()
    filtered = df[df["username"] == user_clean].copy()

    total_events = len(filtered)
    if total_events == 0:
        return {
            "status": "success",
            "username": user_clean,
            "total_events": 0,
            "event_breakdown": {},
            "distinct_ips_used": [],
            "sample_events": [],
            "message": f"No activity recorded for user {user_clean}.",
        }

    breakdown = filtered["event_type"].value_counts().to_dict()
    all_ips = sorted(filtered["source_ip"].dropna().unique().tolist())

    private_ips = []
    external_ips = []
    for ip_str in all_ips:
        if is_ip_private(ip_str):
            private_ips.append(ip_str)
        else:
            external_ips.append(ip_str)

    first_seen = filtered["parsed_timestamp"].min().isoformat()
    last_seen = filtered["parsed_timestamp"].max().isoformat()

    sample_events = (
        filtered[["timestamp", "source_ip", "username", "event_type", "status", "host"]]
        .head(10)
        .to_dict(orient="records")
    )

    return {
        "status": "success",
        "username": user_clean,
        "total_events": total_events,
        "event_breakdown": breakdown,
        "distinct_ips_count": len(all_ips),
        "distinct_ips_used": all_ips[:10],
        "private_ips_used": private_ips[:5],
        "external_ips_used": external_ips[:10],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sample_events": sample_events,
    }


def check_success_after_failures(
    ip: str, user: Optional[str] = None
) -> Dict[str, Any]:
    """Check if any successful login occurred from an IP (and optional user) after failed logins.

    Args:
        ip: IP address to check.
        user: Optional specific username to check.

    Returns:
        Compact dictionary stating whether success was found, timing delta, and relevant events.
    """
    err = _validate_ip(ip)
    if err:
        return {"error": err, "status": "failed"}

    df = get_loaded_logs()
    if df.empty:
        return {"error": "No logs currently loaded.", "status": "failed"}

    ip_clean = ip.strip()
    query = df["source_ip"] == ip_clean
    if user:
        query = query & (df["username"] == user.strip())

    filtered = df[query].sort_values("parsed_timestamp").reset_index(drop=True)

    failures = filtered[filtered["event_type"] == "login_failed"]
    successes = filtered[filtered["event_type"] == "login_success"]

    if failures.empty:
        return {
            "status": "success",
            "success_found": not successes.empty,
            "failed_login_count": 0,
            "success_count": len(successes),
            "message": f"No failed logins found for IP {ip_clean}.",
            "sample_events": successes.head(5).to_dict(orient="records"),
        }

    last_fail_time = failures["parsed_timestamp"].max()
    subsequent_successes = successes[successes["parsed_timestamp"] > last_fail_time]

    success_found = not subsequent_successes.empty
    time_diff_sec = None
    first_succ_time_str = None

    if success_found:
        first_subsequent = subsequent_successes.iloc[0]
        time_diff_sec = round(
            (first_subsequent["parsed_timestamp"] - last_fail_time).total_seconds(), 2
        )
        first_succ_time_str = first_subsequent["parsed_timestamp"].isoformat()

    sample_succ_events = (
        subsequent_successes[["timestamp", "source_ip", "username", "status", "host"]]
        .head(10)
        .to_dict(orient="records")
        if success_found
        else []
    )

    return {
        "status": "success",
        "success_found": success_found,
        "failed_login_count": len(failures),
        "total_successes": len(successes),
        "last_failure_time": last_fail_time.isoformat(),
        "first_subsequent_success_time": first_succ_time_str,
        "seconds_after_last_failure": time_diff_sec,
        "subsequent_success_events": sample_succ_events,
    }


def get_ip_reputation(ip: str) -> Dict[str, Any]:
    """Query deterministic local threat intelligence for an IP address.

    Uses the standard Python ipaddress library to determine classification
    and checks against a local blocklist. Never makes external network calls.

    Args:
        ip: IP address to query.

    Returns:
        Compact dictionary with IP classification, blocklist status, and reputation score.
    """
    err = _validate_ip(ip)
    if err:
        return {"error": err, "status": "failed"}

    ip_clean = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return {"error": f"Invalid IP: {ip_clean}", "status": "failed"}

    is_private = is_ip_private(ip_clean)
    is_public = not is_private

    is_blocklisted = ip_clean in LOCAL_BLOCKLIST
    blocklist_reason = LOCAL_BLOCKLIST.get(ip_clean)

    if is_blocklisted:
        reputation = "Known Malicious"
    elif is_private:
        reputation = "Internal Private"
    elif is_public:
        reputation = "External Public (Neutral)"
    else:
        reputation = "Reserved/Special"

    return {
        "status": "success",
        "ip": ip_clean,
        "is_private": is_private,
        "is_public": is_public,
        "is_blocklisted": is_blocklisted,
        "blocklist_reason": blocklist_reason,
        "reputation": reputation,
    }


def get_time_pattern(entity_type: str, entity_value: str) -> Dict[str, Any]:
    """Analyze temporal distribution and business-hours pattern for an IP or username.

    Args:
        entity_type: Either 'user' or 'ip'.
        entity_value: The username or IP address string.

    Returns:
        Compact summary of business hours ratio (08:00-18:00 UTC) vs off-hours activity.
    """
    clean_type = str(entity_type).strip().lower()
    if clean_type not in ["user", "ip"]:
        return {
            "error": f"Invalid entity_type: '{entity_type}'. Must be 'user' or 'ip'.",
            "status": "failed",
        }

    clean_val = str(entity_value).strip()
    if not clean_val:
        return {"error": "entity_value cannot be empty.", "status": "failed"}

    if clean_type == "ip":
        err = _validate_ip(clean_val)
        if err:
            return {"error": err, "status": "failed"}

    df = get_loaded_logs()
    if df.empty:
        return {"error": "No logs currently loaded.", "status": "failed"}

    col = "username" if clean_type == "user" else "source_ip"
    filtered = df[(df[col] == clean_val) & (df["event_type"] == "login_success")].copy()

    total_logins = len(filtered)
    if total_logins == 0:
        return {
            "status": "success",
            "entity_type": clean_type,
            "entity_value": clean_val,
            "total_successful_logins": 0,
            "business_hours_ratio": 0.0,
            "is_predominantly_business_hours": False,
            "message": f"No successful logins found for {clean_type} '{clean_val}'.",
        }

    hours = filtered["parsed_timestamp"].dt.hour
    biz_count = int(((hours >= 8) & (hours < 18)).sum())
    off_count = total_logins - biz_count
    ratio = round(biz_count / total_logins, 3)

    hourly_dist = hours.value_counts().to_dict()
    # format hourly distribution nicely
    hourly_clean = {int(k): int(v) for k, v in hourly_dist.items()}

    return {
        "status": "success",
        "entity_type": clean_type,
        "entity_value": clean_val,
        "total_successful_logins": total_logins,
        "business_hours_logins": biz_count,
        "off_hours_logins": off_count,
        "business_hours_ratio": ratio,
        "is_predominantly_business_hours": ratio >= 0.75,
        "hourly_distribution": hourly_clean,
    }


# -------------------------------------------------------------
# LangChain Tool Wrappers
# -------------------------------------------------------------
@tool
def tool_get_failed_logins(
    ip: Optional[str] = None,
    user: Optional[str] = None,
    window_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """Query failed logins filtered by IP and/or username with counts and sample events."""
    return get_failed_logins(ip=ip, user=user, window_minutes=window_minutes)


@tool
def tool_get_activity_for_ip(ip: str) -> Dict[str, Any]:
    """Get overall historical activity summary, event breakdown, and sample events for an IP."""
    return get_activity_for_ip(ip=ip)


@tool
def tool_get_activity_for_user(user: str) -> Dict[str, Any]:
    """Get historical login activity, distinct IPs used, and baseline for a username."""
    return get_activity_for_user(user=user)


@tool
def tool_check_success_after_failures(
    ip: str, user: Optional[str] = None
) -> Dict[str, Any]:
    """Check if a successful login occurred after failed logins for an IP and/or username."""
    return check_success_after_failures(ip=ip, user=user)


@tool
def tool_get_ip_reputation(ip: str) -> Dict[str, Any]:
    """Query local threat intelligence and private/public classification for an IP address."""
    return get_ip_reputation(ip=ip)


@tool
def tool_get_time_pattern(entity_type: str, entity_value: str) -> Dict[str, Any]:
    """Analyze temporal distribution and business hours ratio for a user or IP."""
    return get_time_pattern(entity_type=entity_type, entity_value=entity_value)


# Global tool mapping
TOOL_REGISTRY: Dict[str, Any] = {
    "get_failed_logins": get_failed_logins,
    "get_activity_for_ip": get_activity_for_ip,
    "get_activity_for_user": get_activity_for_user,
    "check_success_after_failures": check_success_after_failures,
    "get_ip_reputation": get_ip_reputation,
    "get_time_pattern": get_time_pattern,
}

LANGCHAIN_TOOLS = [
    tool_get_failed_logins,
    tool_get_activity_for_ip,
    tool_get_activity_for_user,
    tool_check_success_after_failures,
    tool_get_ip_reputation,
    tool_get_time_pattern,
]

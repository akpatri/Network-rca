from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import json
import os
import shlex
import sys

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("Network RCA MCP Server")

BASE_DIR = Path(__file__).resolve().parent


def get_log_file_path() -> Path:
    """
    Log file loading priority:
    1. LOG_FILE environment variable
    2. First command-line argument after server.py
    3. server.log in the same folder as server.py
    """
    env_path = os.environ.get("LOG_FILE")
    if env_path:
        return Path(env_path).expanduser().resolve()

    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser().resolve()

    return BASE_DIR / "server.log"


LOG_FILE = get_log_file_path()

SEVERITY_RANK = {
    "INFO": 1,
    "WARN": 2,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
}


def parse_value(value: str) -> Any:
    """Convert values to int/float where possible."""
    if value in {"N/A", "NONE", ""}:
        return value

    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def parse_log_line(line: str) -> dict[str, Any]:
    """
    Parse one key-value log line.

    Example:
    2026-06-29T09:01:00+05:30 host=del-core-sw-01 severity=WARN msg="..."
    """
    line = line.strip()
    if not line:
        return {}

    # shlex handles quoted values like msg="Interface restored after 21 seconds"
    parts = shlex.split(line)
    if not parts:
        return {}

    record: dict[str, Any] = {
        "timestamp": parts[0]
    }

    for token in parts[1:]:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)
        record[key] = parse_value(value)

    return record


def load_logs() -> list[dict[str, Any]]:
    """Read and parse server.log."""
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    records: list[dict[str, Any]] = []

    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as file:
        for line_no, line in enumerate(file, start=1):
            record = parse_log_line(line)
            if record:
                record["line_no"] = line_no
                records.append(record)

    return records


def to_json(data: Any) -> str:
    """Return pretty JSON as MCP tool output."""
    return json.dumps(data, indent=2, ensure_ascii=False)


def severity_at_least(row: dict[str, Any], min_severity: str) -> bool:
    current = str(row.get("severity", "INFO")).upper()
    required = min_severity.upper()
    return SEVERITY_RANK.get(current, 0) >= SEVERITY_RANK.get(required, 3)


def compact_event(row: dict[str, Any]) -> dict[str, Any]:
    """Return useful fields only."""
    return {
        "line_no": row.get("line_no"),
        "timestamp": row.get("timestamp"),
        "severity": row.get("severity"),
        "host": row.get("host"),
        "device_id": row.get("device_id"),
        "device_type": row.get("device_type"),
        "site": row.get("site"),
        "rack": row.get("rack"),
        "interface": row.get("interface"),
        "category": row.get("category"),
        "event": row.get("event"),
        "protocol": row.get("protocol"),
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "vlan": row.get("vlan"),
        "metric": row.get("metric"),
        "value": row.get("value"),
        "threshold": row.get("threshold"),
        "action": row.get("action"),
        "incident_id": row.get("incident_id"),
        "root_cause_hint": row.get("root_cause_hint"),
        "msg": row.get("msg"),
    }


def filter_logs(
    logs: list[dict[str, Any]],
    keyword: str = "",
    severity: str = "",
    incident_id: str = "",
    host: str = "",
    device_id: str = "",
    site: str = "",
    event: str = "",
    category: str = "",
) -> list[dict[str, Any]]:
    """Common log filtering logic."""
    rows = logs

    if incident_id:
        rows = [
            row for row in rows
            if str(row.get("incident_id", "")).lower() == incident_id.lower()
        ]

    if severity:
        rows = [
            row for row in rows
            if str(row.get("severity", "")).lower() == severity.lower()
        ]

    if host:
        rows = [
            row for row in rows
            if str(row.get("host", "")).lower() == host.lower()
        ]

    if device_id:
        rows = [
            row for row in rows
            if str(row.get("device_id", "")).lower() == device_id.lower()
        ]

    if site:
        rows = [
            row for row in rows
            if str(row.get("site", "")).lower() == site.lower()
        ]

    if event:
        rows = [
            row for row in rows
            if str(row.get("event", "")).lower() == event.lower()
        ]

    if category:
        rows = [
            row for row in rows
            if str(row.get("category", "")).lower() == category.lower()
        ]

    if keyword:
        key = keyword.lower()
        rows = [
            row for row in rows
            if key in json.dumps(row, ensure_ascii=False).lower()
        ]

    return rows


def get_incident_groups(logs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in logs:
        incident_id = str(row.get("incident_id", "NONE"))
        if incident_id != "NONE":
            grouped[incident_id].append(row)

    return grouped


@mcp.tool()
def log_stats() -> str:
    """
    Get overall statistics from server.log.

    Returns total records, severity counts, category counts, incident counts,
    top hosts, top sites, and log file path.
    """
    logs = load_logs()

    data = {
        "log_file": str(LOG_FILE),
        "total_records": len(logs),
        "severity_counts": dict(Counter(str(row.get("severity", "UNKNOWN")) for row in logs)),
        "category_counts": dict(Counter(str(row.get("category", "UNKNOWN")) for row in logs)),
        "event_counts_top_15": Counter(str(row.get("event", "UNKNOWN")) for row in logs).most_common(15),
        "incident_counts": dict(Counter(str(row.get("incident_id", "NONE")) for row in logs)),
        "top_hosts": Counter(str(row.get("host", "UNKNOWN")) for row in logs).most_common(10),
        "top_sites": Counter(str(row.get("site", "UNKNOWN")) for row in logs).most_common(10),
    }

    return to_json(data)


@mcp.tool()
def list_incidents() -> str:
    """
    List all incident IDs found in the logs, excluding incident_id=NONE.

    Use this first if you do not know the incident ID.
    """
    logs = load_logs()
    grouped = get_incident_groups(logs)

    incidents = []

    for incident_id, rows in sorted(grouped.items()):
        root_causes = Counter(str(row.get("root_cause_hint", "UNKNOWN")) for row in rows)
        highest_severity = max(
            [str(row.get("severity", "INFO")).upper() for row in rows],
            key=lambda sev: SEVERITY_RANK.get(sev, 0),
        )

        incidents.append({
            "incident_id": incident_id,
            "event_count": len(rows),
            "first_seen": rows[0].get("timestamp"),
            "last_seen": rows[-1].get("timestamp"),
            "highest_severity": highest_severity,
            "probable_root_cause": root_causes.most_common(1)[0][0],
            "affected_sites": sorted(set(str(row.get("site", "UNKNOWN")) for row in rows)),
            "affected_hosts": sorted(set(str(row.get("host", "UNKNOWN")) for row in rows)),
        })

    return to_json(incidents)


@mcp.tool()
def search_logs(
    keyword: str = "",
    severity: str = "",
    incident_id: str = "",
    host: str = "",
    device_id: str = "",
    site: str = "",
    event: str = "",
    category: str = "",
    limit: int = 25,
) -> str:
    """
    Search logs using keyword and optional filters.

    Args:
        keyword: Search text like OSPF, DHCP, CRC, fiber, BGP, SYN, PoE.
        severity: INFO, WARN, ERROR, or CRITICAL.
        incident_id: Example INC-20260629-001.
        host: Example del-core-sw-01.
        device_id: Example SW-DEL-CORE-01.
        site: Example Delhi-DC.
        event: Example LINK_FLAP.
        category: Example INTERFACE.
        limit: Maximum records to return.
    """
    logs = load_logs()
    rows = filter_logs(
        logs=logs,
        keyword=keyword,
        severity=severity,
        incident_id=incident_id,
        host=host,
        device_id=device_id,
        site=site,
        event=event,
        category=category,
    )

    limit = max(1, min(int(limit), 100))

    return to_json({
        "matched_records": len(rows),
        "returned_records": min(len(rows), limit),
        "records": [compact_event(row) for row in rows[:limit]],
    })


@mcp.tool()
def severity_report(min_severity: str = "ERROR", limit: int = 50) -> str:
    """
    Return all logs at or above a minimum severity.

    Args:
        min_severity: INFO, WARN, ERROR, or CRITICAL.
        limit: Maximum records to return.
    """
    logs = load_logs()
    rows = [row for row in logs if severity_at_least(row, min_severity)]

    limit = max(1, min(int(limit), 100))

    return to_json({
        "min_severity": min_severity.upper(),
        "matched_records": len(rows),
        "returned_records": min(len(rows), limit),
        "records": [compact_event(row) for row in rows[:limit]],
    })


@mcp.tool()
def incident_timeline(incident_id: str) -> str:
    """
    Return chronological timeline for one incident.

    Args:
        incident_id: Example INC-20260629-001.
    """
    logs = load_logs()
    rows = filter_logs(logs, incident_id=incident_id)

    if not rows:
        return to_json({
            "incident_id": incident_id,
            "found": False,
            "message": "No logs found for this incident_id."
        })

    return to_json({
        "incident_id": incident_id,
        "found": True,
        "event_count": len(rows),
        "first_seen": rows[0].get("timestamp"),
        "last_seen": rows[-1].get("timestamp"),
        "timeline": [compact_event(row) for row in rows],
    })


@mcp.tool()
def find_root_cause(incident_id: str) -> str:
    """
    Find probable root cause for one incident.

    The tool uses:
    - root_cause_hint
    - error/critical events
    - correlated alert events
    - recovery/resolution events
    - affected hosts/interfaces/sites

    Args:
        incident_id: Example INC-20260629-001.
    """
    logs = load_logs()
    rows = filter_logs(logs, incident_id=incident_id)

    if not rows:
        return to_json({
            "incident_id": incident_id,
            "found": False,
            "message": "No logs found for this incident_id."
        })

    root_causes = Counter(str(row.get("root_cause_hint", "UNKNOWN")) for row in rows)
    severity_counts = Counter(str(row.get("severity", "UNKNOWN")) for row in rows)
    category_counts = Counter(str(row.get("category", "UNKNOWN")) for row in rows)
    event_counts = Counter(str(row.get("event", "UNKNOWN")) for row in rows)

    highest_severity = max(
        [str(row.get("severity", "INFO")).upper() for row in rows],
        key=lambda sev: SEVERITY_RANK.get(sev, 0),
    )

    probable_root_cause = root_causes.most_common(1)[0][0]

    key_evidence = []
    for row in rows:
        event_text = str(row.get("event", "")).upper()
        severity_text = str(row.get("severity", "INFO")).upper()

        if (
            SEVERITY_RANK.get(severity_text, 0) >= SEVERITY_RANK["ERROR"]
            or "CORRELATED" in event_text
            or "RESOLVED" in event_text
            or "NORMAL" in event_text
            or "RESTORED" in event_text
            or "ROLLBACK" in event_text
        ):
            key_evidence.append(compact_event(row))

    resolution_events = []
    for row in rows:
        combined = " ".join([
            str(row.get("event", "")),
            str(row.get("action", "")),
            str(row.get("msg", "")),
        ]).upper()

        if any(word in combined for word in [
            "RESOLVED", "NORMAL", "RESTORED", "RECOVERED",
            "CLOSED", "ROLLBACK", "FIXED", "GRANTED"
        ]):
            resolution_events.append(compact_event(row))

    affected_hosts = sorted(set(str(row.get("host", "UNKNOWN")) for row in rows))
    affected_devices = sorted(set(str(row.get("device_id", "UNKNOWN")) for row in rows))
    affected_sites = sorted(set(str(row.get("site", "UNKNOWN")) for row in rows))
    affected_interfaces = sorted(set(str(row.get("interface", "UNKNOWN")) for row in rows))

    return to_json({
        "incident_id": incident_id,
        "found": True,
        "probable_root_cause": probable_root_cause,
        "highest_severity": highest_severity,
        "first_seen": rows[0].get("timestamp"),
        "last_seen": rows[-1].get("timestamp"),
        "total_events": len(rows),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "top_events": event_counts.most_common(10),
        "affected_sites": affected_sites,
        "affected_hosts": affected_hosts,
        "affected_devices": affected_devices,
        "affected_interfaces": affected_interfaces,
        "key_evidence": key_evidence[:25],
        "resolution_events": resolution_events,
        "rca_summary": (
            f"Incident {incident_id} is most likely caused by: {probable_root_cause}. "
            f"It started around {rows[0].get('timestamp')} and last related event was around "
            f"{rows[-1].get('timestamp')}. Highest severity observed: {highest_severity}. "
            f"Affected hosts: {', '.join(affected_hosts)}."
        ),
    })


@mcp.tool()
def device_health(device: str) -> str:
    """
    Summarize health of a device by hostname or device_id.

    Args:
        device: Hostname like del-core-sw-01 or device_id like SW-DEL-CORE-01.
    """
    logs = load_logs()

    rows = [
        row for row in logs
        if str(row.get("host", "")).lower() == device.lower()
        or str(row.get("device_id", "")).lower() == device.lower()
    ]

    if not rows:
        return to_json({
            "device": device,
            "found": False,
            "message": "No logs found for this device."
        })

    bad_rows = [
        row for row in rows
        if severity_at_least(row, "WARN")
    ]

    incident_ids = sorted(set(str(row.get("incident_id", "NONE")) for row in rows))

    return to_json({
        "device": device,
        "found": True,
        "total_events": len(rows),
        "warning_or_worse_events": len(bad_rows),
        "first_seen": rows[0].get("timestamp"),
        "last_seen": rows[-1].get("timestamp"),
        "severity_counts": dict(Counter(str(row.get("severity", "UNKNOWN")) for row in rows)),
        "top_events": Counter(str(row.get("event", "UNKNOWN")) for row in rows).most_common(10),
        "incident_ids": incident_ids,
        "important_events": [compact_event(row) for row in bad_rows],
    })


@mcp.tool()
def top_noisy_devices(limit: int = 10) -> str:
    """
    Show devices producing the most WARN/ERROR/CRITICAL logs.

    Args:
        limit: Number of devices to return.
    """
    logs = load_logs()

    noisy_rows = [
        row for row in logs
        if severity_at_least(row, "WARN")
    ]

    host_counts = Counter(str(row.get("host", "UNKNOWN")) for row in noisy_rows)

    result = []

    for host, count in host_counts.most_common(max(1, min(int(limit), 50))):
        host_rows = [row for row in noisy_rows if str(row.get("host", "UNKNOWN")) == host]

        result.append({
            "host": host,
            "warning_or_worse_count": count,
            "severity_counts": dict(Counter(str(row.get("severity", "UNKNOWN")) for row in host_rows)),
            "incident_ids": sorted(set(str(row.get("incident_id", "NONE")) for row in host_rows)),
            "top_events": Counter(str(row.get("event", "UNKNOWN")) for row in host_rows).most_common(5),
        })

    return to_json(result)


@mcp.tool()
def metric_threshold_breaches(limit: int = 50) -> str:
    """
    Return logs where numeric metric value breached numeric threshold.

    For most metrics, breach means value > threshold.
    For negative optical rx_power_dbm values, this tool also handles low power cases.
    """
    logs = load_logs()
    breaches = []

    for row in logs:
        value = row.get("value")
        threshold = row.get("threshold")
        metric = str(row.get("metric", ""))

        if not isinstance(value, (int, float)) or not isinstance(threshold, (int, float)):
            continue

        breached = False

        # For optical power, lower/more negative is worse.
        if "rx_power" in metric:
            breached = value < threshold
        else:
            breached = value > threshold

        if breached:
            breaches.append(compact_event(row))

    limit = max(1, min(int(limit), 100))

    return to_json({
        "matched_records": len(breaches),
        "returned_records": min(len(breaches), limit),
        "records": breaches[:limit],
    })


@mcp.tool()
def ask_rca(question: str) -> str:
    """
    Simple natural-language helper over the log file.

    Example questions:
    - What caused INC-20260629-001?
    - Show OSPF errors.
    - Which devices had critical events?
    - Show DHCP issue.
    - Find PoE problem.
    """
    logs = load_logs()
    q = question.lower()

    # Find explicit incident ID in question.
    for row in logs:
        incident_id = str(row.get("incident_id", "NONE"))
        if incident_id != "NONE" and incident_id.lower() in q:
            if any(word in q for word in ["cause", "root", "why", "rca", "happen", "summary"]):
                return find_root_cause(incident_id)
            return incident_timeline(incident_id)

    if "incident" in q and "list" in q:
        return list_incidents()

    if "stats" in q or "summary" in q or "count" in q:
        return log_stats()

    if "critical" in q:
        return severity_report("CRITICAL", 50)

    if "error" in q:
        return severity_report("ERROR", 50)

    keywords = [
        "ospf", "bgp", "dhcp", "poe", "syn", "flood", "cpu", "firewall",
        "packet", "latency", "crc", "fiber", "mtu", "wireless", "ap",
        "vlan", "interface", "link", "route", "sfp", "power"
    ]

    for keyword in keywords:
        if keyword in q:
            return search_logs(keyword=keyword, limit=25)

    return search_logs(keyword=question, limit=25)


@mcp.resource("logs://server")
def get_raw_log_file() -> str:
    """
    Return the raw server.log content as an MCP resource.
    """
    return LOG_FILE.read_text(encoding="utf-8", errors="replace")


@mcp.resource("logs://incidents")
def get_incidents_resource() -> str:
    """
    Return incident list as an MCP resource.
    """
    return list_incidents()


if __name__ == "__main__":
    # Important:
    # Do not use normal print() for debugging in MCP STDIO mode.
    # stdout is reserved for JSON-RPC protocol messages.
    # Use stderr for debug logs.
    if not LOG_FILE.exists():
        print(f"WARNING: Log file not found: {LOG_FILE}", file=sys.stderr)

    mcp.run()

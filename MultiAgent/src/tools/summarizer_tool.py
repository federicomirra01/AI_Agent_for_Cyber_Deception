from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

def svc_str(proto: str, port: Any) -> str:
    p = (proto or "").lower()
    return f"{p}/{port}"

def _is_scan_signature(signature: Optional[str]) -> bool:
    return "scan" in (signature or "").lower()

def build_security_summary(
    data: Dict[str, Any],
    vulnerable_containers: List[Dict[str, Any]],
    previous_snapshot: Dict[str, Any] = {},
    last_exposed: Dict[str, Any] = {}
) -> Dict[str, Any]:
    """
    data: dict with keys 'alerts', 'time_window_minutes', 'timestamp', 'total_events'
    vulnerable_containers: {'vulnerable_containers': [{'service':..., 'ip':..., 'ports':[...]}]}
    previous_snapshot: optional dict used to mark 'new' vs not new.
        Keys are "ip|signature|service|src_ip|src_port".
        If key exists -> new=False, else new=True.
    """
    prev = previous_snapshot or {}

    # Build IP -> service_name map
    ip_to_service = {}
    for vc in vulnerable_containers or []:
        ip_to_service[vc["ip"]] = vc["service"]    

    last_exposed_ip = None
    last_exposed_service_name = None
    if isinstance(last_exposed, dict):
        last_exposed_ip = last_exposed.get("ip")
        last_exposed_service_name = last_exposed.get("service")

    
    # Group alerts by target host (service host)
    host_buckets: Dict[str, Dict[str, Any]] = {}
    for a in data.get("alerts", []):
        dest_ip = a.get("dest_ip")
        host_key = dest_ip

        if host_key not in host_buckets:
            host_buckets[host_key] = {
                "ip": host_key,
                "service": ip_to_service.get(host_key, "service not identified"),
            }

    # Ensure currently_exposed host is present and named as requested
    if last_exposed_ip is not None:
        if last_exposed_ip not in host_buckets:
            host_buckets[last_exposed_ip] = {
                "ip": last_exposed_ip,
                "service": last_exposed_service_name or ip_to_service.get(last_exposed_ip, "service not identified"),
                "compromise_indicators": []
            }
        else:
            # Override service_name with the currently exposed service
            if last_exposed_service_name:
                host_buckets[last_exposed_ip]["service"] = last_exposed_service_name

    # 4) Collapse duplicates: same signature + service + src_ip within the same host
    #    Use an index per host for fast aggregation.
    aggregate_index: Dict[str, Dict[Tuple[str, str, Any], Dict[str, Any]]] = defaultdict(dict)
    for a in data.get("alerts", []):
        dest_ip   = a.get("dest_ip")
        dest_port = a.get("dest_port")
        proto     = a.get("proto", "tcp")
        signature = a.get("signature") or ""
        severity  = a.get("severity", 3)
        src_ip    = a.get("src_ip")
        src_port  = a.get("src_port")
        payload   = a.get("payload") or ""

        # Skip if we don't have basic addressing
        if dest_ip is None or dest_port is None or src_ip is None or src_port is None:
            continue

        service = svc_str(proto, dest_port)
        host_bucket = host_buckets.get(dest_ip)
        if not host_bucket:
            # If an alert references an unseen dest_ip (odd), create it now
            host_buckets[dest_ip] = {
                "ip": dest_ip,
                "service": ip_to_service.get(dest_ip, "service not identified"),
            }
            host_bucket = host_buckets[dest_ip]

        # Key to collapse duplicates inside the same host
        k = (signature, service, src_ip)

        entry = aggregate_index[dest_ip].get(k)
        if not entry:
            key_for_new = f"{dest_ip}|{signature}|{service}|{src_ip}"
            entry = {
                "signature": signature,
                "dest_port": dest_port,
                "count": 0,
                "severity": severity,
                "src_ip": src_ip,
                "src_ports": [src_port],
                "payload": "",
                "new": (key_for_new not in prev),
            }
            aggregate_index[dest_ip][k] = entry

        # Increase count and keep the highest severity *number* (but you want sorting asc later)
        entry["count"] += 1
        # If a later alert has a different severity, keep the minimum numeric (best reflects "highest risk" when sorted asc?).
        # We'll preserve the minimum to reflect the strongest classification (1 = highest).
        entry["severity"] = min(entry["severity"], severity)

        if src_port not in entry["src_ports"]:
            entry["src_ports"].append(src_port)
        # Capture payload & evidence quotes if present; keep the latest non-empty payload
        if payload:
            entry["payload"] = payload[:1000]
            # refresh quotes to match payload content

    # Move collapsed indicators into each host bucket and sort:
    # 1) severity asc
    # 2) non-scan before scan (same severity)
    # 3) signature alpha for stable ordering
    for dest_ip, idx in aggregate_index.items():
        indicators = list(idx.values())
        indicators.sort(
            key=lambda x: (
                x.get("severity", 99),
                1 if _is_scan_signature(x.get("signature", "")) else 0,  # non-scan first
                x.get("signature", "")
            )
        )
        host_buckets[dest_ip]["compromise_indicators"] = indicators

    # Order hosts with selected_container first, then known container, then others; stable by IP
    def host_sort_key(h: Dict[str, Any]):
        ip = h.get("ip")
        ip_str = ip or ""
        return (
            0 if (last_exposed_ip is not None and ip == last_exposed_ip) else 1,  # selected_container always first
            0 if ip in ip_to_service else 1,                                      # vulnerable IPs next
            ip_str                                                                    # stable by IP
        )

    # 6) Order hosts: prioritize exposed container first, then others; stable by IP
    alerts = list(host_buckets.values())
    alerts.sort(key=host_sort_key)

    return {"security_events": alerts}


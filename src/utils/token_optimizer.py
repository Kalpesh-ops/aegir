def prune_scan_data(scan_data):
    """
    Removes low-value data to save API tokens and reduce noise for the AI.
    """
    if not scan_data:
        return {}

    pruned = {
        "scan_stats": {
            "uphosts": scan_data.get("scan_stats", {}).get("uphosts"),
            "timestr": scan_data.get("scan_stats", {}).get("timestr"),
        },
        "open_ports": [],
        "os_match": scan_data.get("os_match", "Unknown"),
        "firewall_status": scan_data.get("firewall_analysis", {}).get(
            "firewall_status"
        ),
    }

    # Only extract OPEN ports and ESSENTIAL service info
    hosts = scan_data.get("hosts", [])
    for host in hosts:
        for port in host.get("open_ports", []):
            pruned["open_ports"].append(
                {
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    # Only include vuln scripts if they found something
                    "vulnerabilities": port.get("vulnerabilities_found", ""),
                }
            )

    return pruned

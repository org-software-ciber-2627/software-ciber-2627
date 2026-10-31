import ipaddress


def is_valid_ip(ip_string):
    """Return whether ``ip_string`` is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
    except (ValueError, TypeError):
        return False
    return True


def filter_alerts_by_ip(alerts, target_ip):
    """Return alerts whose source IP matches ``target_ip``."""
    if not is_valid_ip(target_ip):
        raise ValueError(f"Invalid IP address: {target_ip}")

    return [
        alert
        for alert in alerts
        if alert["source_ip"] == target_ip
    ]

import ipaddress

def filter(key_chain: str):
    """Registers filters with preconditions."""
    def wrapper(pre):
        def inner(alerts, item):
            # pre is a precondition for the filter to execute (input checks, basically)
            pre(alerts, item)
            # Gets final item from an ordered list of keys
            get_item = lambda x,y: x if len(y) == 0 else get_item(x[y[0]], y[1:])
            keys = key_chain.split(".")
            return [alert for alert in alerts if get_item(alert, keys) == item]
        return inner
    return wrapper

def is_valid_ip(ip_string):
    """Return whether ``ip_string`` is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
    except (ValueError, TypeError):
        return False
    return True

@filter("event_type")
def filter_alerts_by_event_type(alerts, event_type):
    """Return alerts whose event type matches ``event_type``."""
    return

@filter("severity")
def filter_alerts_by_severity(alerts, severity):
    """Return alerts whose severity matches ``severity``."""
    if not severity.lower() in ("critical", "high", "medium", "low"):
        raise ValueError(f"Invalid severity value: {severity}")

@filter("details.source_ip")
def filter_alerts_by_ip(alerts, source_ip):
    """Return alerts whose source IP matches ``source_ip``."""
    if not is_valid_ip(source_ip):
        raise ValueError(f"Invalid IP address: {source_ip}")
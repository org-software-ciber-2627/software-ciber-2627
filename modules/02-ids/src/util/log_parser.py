import re

LOG_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<service>[^\[]+)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$"
)

FAILED_LOGIN = re.compile(
    r"(?:Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"|authentication failure;.*?rhost=)"
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?: port (?P<source_port>\d+))?"
)
ACCEPTED_LOGIN = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})(?: port (?P<source_port>\d+))?"
)
INVALID_USER = re.compile(
    r"Invalid user (?P<username>\S*) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SOURCE_CONNECTION = re.compile(
    r"(?:from|by) (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?: port (?P<source_port>\d+))?"
)


def parse_log_line(line):
    """Convierte una línea syslog en un diccionario serializable a JSON."""
    match = LOG_PREFIX.match(line.strip())
    if not match:
        return None

    event = {
        "timestamp": match.group("timestamp"),
        "service": match.group("service"),
        "event_type": "log",
    }
    message = match.group("message")

    if "Failed password" in message or "authentication failure" in message:
        event["event_type"] = "failed_login"
        details = FAILED_LOGIN.search(message)
        if details:
            _add_details(event, details)
    elif message.startswith("Accepted "):
        event["event_type"] = "successful_login"
        details = ACCEPTED_LOGIN.search(message)
        if details:
            _add_details(event, details)
    elif message.startswith("Invalid user "):
        event["event_type"] = "invalid_user"
        details = INVALID_USER.search(message)
        if details:
            _add_details(event, details)
    elif "authentication attempts exceeded" in message:
        event["event_type"] = "authentication_limit_exceeded"
        details = SOURCE_CONNECTION.search(message)
        if details:
            _add_details(event, details)
    elif "Connection closed" in message or "Disconnected from" in message:
        event["event_type"] = "connection_closed"
        details = SOURCE_CONNECTION.search(message)
        if details:
            _add_details(event, details)

    return event


def parse_log_lines(lines):
    """Convierte varias líneas syslog en una lista de eventos JSON."""
    return [
        event
        for line in lines
        if (event := parse_log_line(line)) is not None
    ]


def _add_details(event, details):
    for field in ("username", "source_ip", "source_port"):
        value = details.groupdict().get(field)
        if value:
            event[field] = int(value) if field == "source_port" else value

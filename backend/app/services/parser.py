import re

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

def parse_apache_log(file_path: str):
    parsed_logs = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as logfile:
        for line in logfile:
            match = APACHE_PATTERN.match(line)

            if match:
                parsed_logs.append(match.groupdict())

    return parsed_logs
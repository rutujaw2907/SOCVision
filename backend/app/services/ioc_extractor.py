import re
from urllib.parse import unquote


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\"']+",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)


def extract_iocs(log):
    """
    Extract potentially useful Indicators of Compromise
    from a parsed HTTP log record.
    """

    path = log.get("path", "")

    decoded_path = unquote(path)

    combined_text = f"{path} {decoded_path}"

    ips = list(set(IP_PATTERN.findall(combined_text)))

    urls = list(set(URL_PATTERN.findall(combined_text)))

    domains = list(set(DOMAIN_PATTERN.findall(combined_text)))

    return {
        "ips": ips,
        "urls": urls,
        "domains": domains
    }
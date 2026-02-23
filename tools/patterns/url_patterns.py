import re

# URL regex pattern to detect links
URL_PATTERN = re.compile(
    r"\b(?:https?://|ftp://)?"  # optional scheme
    r"(?:www\.)?"  # optional www
    r"(?:"  # domain or IP
    r"(?:[a-zA-Z0-9-]{1,63}\.)+"  # subdomains
    r"[a-zA-Z]{2,63}"  # TLD
    r"|"  # OR
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r")"
    r"(?::\d{2,5})?"  # optional port
    r"(?:/[^\s]*)?"  # optional path
    r"\b",
    re.IGNORECASE,
)
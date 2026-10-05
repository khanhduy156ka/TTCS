import re
from ipaddress import ip_address
from urllib.parse import urlparse


_SHA256_PATTERN = re.compile(
    r"^[A-Fa-f0-9]{64}$"
)

_DOMAIN_LABEL_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
)


def is_public_ip(value: str) -> bool:
    try:
        ip = ip_address(value)
    except ValueError:
        return False

    return ip.is_global


def is_sha256(value: str) -> bool:
    return (
        _SHA256_PATTERN.fullmatch(
            value.strip()
        )
        is not None
    )


def is_valid_domain(value: str) -> bool:
    candidate = (
        value.strip()
        .lower()
        .rstrip(".")
    )

    if (
        not candidate
        or len(candidate) > 253
    ):
        return False

    # Literal IP khong duoc tinh la domain
    try:
        ip_address(candidate)
        return False
    except ValueError:
        pass

    labels = candidate.split(".")

    if len(labels) < 2:
        return False

    return all(
        _DOMAIN_LABEL_PATTERN.fullmatch(label)
        is not None
        for label in labels
    )


def is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(
            value.strip()
        )
    except ValueError:
        return False

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return False

    if not parsed.hostname:
        return False

    hostname = parsed.hostname

    try:
        ip_address(hostname)
        return True
    except ValueError:
        return is_valid_domain(hostname)

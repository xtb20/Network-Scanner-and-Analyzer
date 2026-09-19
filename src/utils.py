"""Formatting helpers shared by callers and reports."""
from ipaddress import ip_address


def normalize_ip(value: str) -> str:
    return str(ip_address(value))


def hex_dump(data: bytes, limit: int = 64) -> str:
    if limit < 0:
        raise ValueError("limit must be nonnegative")
    return data[:limit].hex(" ")

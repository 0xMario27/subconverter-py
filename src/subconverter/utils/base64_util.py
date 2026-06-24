"""Base64 encode/decode utilities."""

import base64
import re


def base64_encode(data: str) -> str:
    """Standard base64 encode."""
    return base64.b64encode(data.encode()).decode()


def base64_decode(data: str) -> str:
    """Standard base64 decode, with padding fix."""
    # Add padding if needed
    missing = len(data) % 4
    if missing:
        data += '=' * (4 - missing)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""


def url_safe_base64_encode(data: str) -> str:
    """URL-safe base64 encode."""
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')


def url_safe_base64_decode(data: str) -> str:
    """URL-safe base64 decode, with padding fix."""
    missing = len(data) % 4
    if missing:
        data += '=' * (4 - missing)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""

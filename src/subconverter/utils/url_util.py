"""URL encode/decode utilities."""

import urllib.parse


def url_encode(data: str) -> str:
    """URL encode a string."""
    return urllib.parse.quote(data, safe='')


def url_decode(data: str) -> str:
    """URL decode a string."""
    return urllib.parse.unquote(data)


def get_url_arg(query_string: str, key: str) -> str:
    """Extract a URL argument from a query string."""
    params = urllib.parse.parse_qs(query_string)
    values = params.get(key, [''])
    return values[0] if values else ''

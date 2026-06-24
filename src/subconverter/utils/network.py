"""HTTP request utilities (replacing libcurl from C++ version)."""

import hashlib
import os
import time
from typing import Optional, Dict

import requests

from .logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_VERBOSE
from .string_util import is_link, starts_with, ends_with, file_exist, file_get, file_write, str_find
from .url_util import url_decode

# Global settings access
_global_settings = None


def set_global_settings(settings):
    global _global_settings
    _global_settings = settings


def get_global_settings():
    return _global_settings


VERSION = "0.1.0"
USER_AGENT = f"subconverter-py/{VERSION}"


def get_system_proxy() -> str:
    """Get system proxy or configured proxy."""
    if _global_settings:
        return _global_settings.proxy_config or ""
    return ""


def parse_proxy(source: str) -> str:
    """Parse proxy setting string."""
    if source == "SYSTEM":
        return get_system_proxy()
    elif source == "NONE":
        return ""
    return source


def get_md5(data: str) -> str:
    """Compute MD5 hash of a string."""
    return hashlib.md5(data.encode()).hexdigest()


def web_get(url: str, proxy: str = "", cache_ttl: int = 0,
            response_headers: Optional[Dict] = None,
            request_headers: Optional[Dict] = None) -> str:
    """
    Fetch content from URL with optional caching.

    Args:
        url: URL to fetch
        proxy: Proxy URL
        cache_ttl: Cache TTL in seconds (0 = no cache)
        response_headers: Output dict for response headers
        request_headers: Additional request headers

    Returns:
        Response content as string
    """
    if starts_with(url, "data:"):
        return _data_get(url)

    # Cache system
    if cache_ttl > 0:
        os.makedirs("cache", exist_ok=True)
        url_md5 = get_md5(url)
        cache_path = f"cache/{url_md5}"
        header_path = f"{cache_path}_header"

        if os.path.isfile(cache_path):
            mtime = os.path.getmtime(cache_path)
            now = time.time()
            if now - mtime <= cache_ttl:
                write_log(0, f"CACHE HIT: '{url}', using local cache.")
                if response_headers is not None:
                    hdr = file_get(header_path)
                    # parse headers
                return file_get(cache_path)
            write_log(0, f"CACHE MISS: '{url}', TTL timeout, creating new cache.")
        else:
            write_log(0, f"CACHE NOT EXIST: '{url}', creating new cache.")

        content = _curl_get(url, proxy, response_headers, request_headers)
        if response_headers and 'status_code' in response_headers and response_headers['status_code'] == 200:
            file_write(cache_path, content, True)
            if response_headers:
                import json
                file_write(header_path, json.dumps(dict(response_headers.get('headers', {}))), True)
        elif file_exist(cache_path):
            gs = _global_settings
            if gs and gs.serve_cache_on_fetch_fail:
                write_log(0, "Fetch failed. Serving cached content.")
                content = file_get(cache_path)
        return content

    return _curl_get(url, proxy, response_headers, request_headers)


def _data_get(url: str) -> str:
    """Handle data: URIs."""
    if not starts_with(url, "data:"):
        return ""
    comma = url.find(',')
    if comma == -1 or comma == len(url) - 1:
        return ""
    data = url_decode(url[comma + 1:])
    prefix = url[:comma]
    if ends_with(prefix, ";base64"):
        from .base64_util import url_safe_base64_decode
        return url_safe_base64_decode(data)
    return data


def _curl_get(url: str, proxy: str = "", response_headers: Optional[Dict] = None,
              request_headers: Optional[Dict] = None) -> str:
    """
    Perform HTTP GET request.

    Returns content string.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "SubConverter-Request": "1",
        "SubConverter-Version": VERSION,
    }
    if request_headers:
        headers.update(request_headers)

    proxies = None
    real_url = url
    if proxy:
        if starts_with(proxy, "cors:"):
            headers["X-Requested-With"] = f"subconverter-py {VERSION}"
            real_url = proxy[5:] + url
        else:
            proxies = {"http": proxy, "https": proxy}

    try:
        gs = _global_settings
        timeout = 15
        r = requests.get(real_url, headers=headers, proxies=proxies,
                         timeout=timeout, verify=False)
        if response_headers is not None:
            response_headers['status_code'] = r.status_code
            response_headers['headers'] = dict(r.headers)
        if r.status_code == 200:
            return r.text
        return "" if gs is None or not gs.api_mode else r.text
    except requests.RequestException as e:
        write_log(0, f"HTTP request failed: {url} - {e}", LOG_LEVEL_WARNING)
    return ""


def web_post(url: str, data: str = "", proxy: str = "",
             request_headers: Optional[Dict] = None) -> tuple:
    """Perform HTTP POST request."""
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json;charset=utf-8",
    }
    if request_headers:
        headers.update(request_headers)

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        r = requests.post(url, data=data.encode(), headers=headers,
                         proxies=proxies, timeout=30, verify=False)
        return r.status_code, r.text
    except requests.RequestException as e:
        write_log(0, f"HTTP POST failed: {url} - {e}", LOG_LEVEL_WARNING)
        return -1, ""


def web_patch(url: str, data: str = "", proxy: str = "",
              request_headers: Optional[Dict] = None) -> tuple:
    """Perform HTTP PATCH request."""
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json;charset=utf-8",
    }
    if request_headers:
        headers.update(request_headers)

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        r = requests.patch(url, data=data.encode(), headers=headers,
                          proxies=proxies, timeout=30, verify=False)
        return r.status_code, r.text
    except requests.RequestException as e:
        write_log(0, f"HTTP PATCH failed: {url} - {e}", LOG_LEVEL_WARNING)
        return -1, ""


# Disable SSL warnings for internal proxy tools
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

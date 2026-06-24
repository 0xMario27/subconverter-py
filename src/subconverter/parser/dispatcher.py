"""Main proxy link dispatcher - routes to the correct type parser."""

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.string_util import starts_with
from .common import common_construct
from .proxy_types import (
    explode_ss, explode_ssr, explode_vmess, explode_trojan, explode_vless,
    explode_hysteria, explode_hysteria2, explode_tuic,
    explode_socks, explode_http_link, explode_snell, explode_wireguard,
    explode_anytls, explode_mieru, explode_tg,
)


# Mapping from URL prefix to parser function
_PARSER_MAP = [
    ("ss://", explode_ss),
    ("ssr://", explode_ssr),
    ("vmess://", explode_vmess),
    ("trojan://", explode_trojan),
    ("vless://", explode_vless),
    ("hysteria2://", explode_hysteria2),
    ("hysteria://", explode_hysteria),
    ("tuic://", explode_tuic),
    ("snell://", explode_snell),
    ("wireguard://", explode_wireguard),
    ("socks5://", explode_socks),
    ("socks://", explode_socks),
    ("anytls://", explode_anytls),
    ("mieru://", explode_mieru),
    ("https://", explode_http_link),
    ("http://", explode_http_link),
    ("tg://", explode_tg),
]


def explode(link: str, node: Proxy) -> bool:
    """Parse a single proxy link and populate the node. Returns True if successful."""
    link_lower = link.lower()
    for prefix, parser in _PARSER_MAP:
        if link_lower.startswith(prefix):
            parser(link, node)
            break

    return node.Type != ProxyType.Unknown

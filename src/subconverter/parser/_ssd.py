"""SSD (ShadowsocksD) link parsing."""

from typing import List

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.base64_util import base64_decode
from ..utils.string_util import starts_with, trim
from .constructors import ss_construct


def explode_ssd(ssd_link: str, default_group: str = "") -> List[Proxy]:
    """Parse SSD links: ssd://base64..."""
    if starts_with(ssd_link, "ssd://"):
        ssd_link = ssd_link[6:]
    decoded = base64_decode(ssd_link)
    if not decoded:
        return []
    nodes = []
    lines = decoded.strip().split('\n')
    for line in lines:
        line = trim(line)
        if not line:
            continue
        parts = line.split(':')
        if len(parts) >= 4:
            node = Proxy()
            ss_construct(node, default_group or DEFAULT_GROUPS[ProxyType.Shadowsocks],
                         parts[0], parts[0], parts[1], parts[3], parts[2])
            nodes.append(node)
    return nodes

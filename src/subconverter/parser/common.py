"""Common helper functions for proxy parsing."""

from typing import Tuple

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.url_util import url_decode
from ..utils.string_util import remove_brackets, to_int


def extract_remark(link: str) -> Tuple[str, str]:
    """Extract #remark from link. Returns (link_without_remark, remark)."""
    remark = ""
    pos = link.rfind("#")
    if pos != -1:
        remark = url_decode(link[pos + 1:])
        link = link[:pos]
    pos = link.find("#")
    if pos != -1:
        link = link[:pos]
    return link, remark


def common_construct(node: Proxy, ptype: ProxyType, group: str, remarks: str,
                     server: str, port: str, udp=None, tfo=None, scv=None,
                     tls13=None, underlying_proxy=""):
    """Common proxy node construction."""
    node.Type = ptype
    node.Group = group
    node.Remark = remarks
    node.Hostname = remove_brackets(server)
    node.Port = to_int(port) if port else 0
    node.UDP = udp
    node.TCPFastOpen = tfo
    node.AllowInsecure = scv
    node.TLS13 = tls13
    node.UnderlyingProxy = underlying_proxy

"""Surge configuration generator."""

from typing import List, Optional

from ..config.models import Proxy, ProxyType
from ..config.settings import ProxyGroupConfig
from ..utils.string_util import trim
from .common import ExtraSettings, expand_group_rules
from .ruleconvert import convert_ruleset, RULESET_SURGE


def proxy_to_surge(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List,
                   extra_groups: List[ProxyGroupConfig],
                   surge_ver: int, settings: ExtraSettings) -> str:
    """Generate Surge configuration."""
    result = []
    if base_conf:
        result.append(base_conf)

    # [Proxy] section
    result.append("[Proxy]")
    for node in nodes:
        line = _surge_proxy(node)
        if line:
            result.append(line)

    # [Proxy Group] section
    result.append("[Proxy Group]")
    all_remark_names = [n.Remark for n in nodes if n.Remark]
    all_group_names = {g.Name for g in extra_groups}

    for g in extra_groups:
        expanded = expand_group_rules(g.Proxies, nodes, all_remark_names, all_group_names)
        if not expanded:
            continue
        proxies_str = ', '.join(expanded)
        group_line = f"{g.Name} = {str(g.Type)}, {proxies_str}"
        if g.Url:
            group_line += f", url = {g.Url}, interval = {g.Interval}"
        result.append(group_line)

    # [Rule] section
    if ruleset_content:
        result.append("[Rule]")
        for rc in ruleset_content:
            content = rc.rule_content or ""
            if not content:
                continue

            rule_path = rc.rule_path or ""
            if rule_path.startswith('http://') or rule_path.startswith('https://'):
                interval = rc.update_interval or 86400
                result.append(f'RULE-SET,{rule_path},"{rc.rule_group}",update-interval={interval}')
                continue

            if rule_path.startswith('inline:') or content.startswith('GEOIP') or content.startswith('FINAL'):
                rule_text = content
                if rule_text == 'MATCH':
                    rule_text = 'FINAL'
                result.append(f"{rule_text},{rc.rule_group}")
                continue

            converted = convert_ruleset(content, rc.rule_type or RULESET_SURGE)
            for line in converted.strip().split('\n'):
                line = trim(line)
                if not line or line[0] in (';', '#') or line.startswith('//'):
                    continue
                parts = line.split(',')
                if len(parts) >= 2 and trim(parts[-1]).lower() == 'no-resolve':
                    core = ','.join(parts[:-1])
                    result.append(f"{core},{rc.rule_group},no-resolve")
                else:
                    result.append(f"{line},{rc.rule_group}")

    result.append("[Host]")
    result.append("localhost = 127.0.0.1")
    result.append("[URL Rewrite]")
    result.append("^http://www.google.cn/generate_204 https://www.google.com/generate_204 header")
    result.append("[MITM]")
    result.append("skip-server-cert-validation = true")

    return '\n'.join(result) + '\n'


# ==================== Surge Proxy Builder ====================

def _surge_proxy(node: Proxy) -> Optional[str]:
    """Convert proxy node to Surge format line."""
    name = node.Remark or f"{node.Hostname}:{node.Port}"
    host = node.Hostname
    port = str(node.Port)
    pw = node.Password

    if node.Type == ProxyType.Shadowsocks:
        return f"{name} = ss, {host}, {port}, encrypt-method={node.EncryptMethod}, password={pw}"
    elif node.Type == ProxyType.ShadowsocksR:
        return f"{name} = custom, {host}, {port}, {node.EncryptMethod}, {pw}, https://raw.githubusercontent.com/ConnersHua/SSRouter/master/SSR.module"
    elif node.Type == ProxyType.VMess:
        return _surge_vmess(name, host, port, node)
    elif node.Type == ProxyType.Trojan:
        return _surge_trojan(name, host, port, node)
    elif node.Type == ProxyType.SOCKS5:
        return _surge_socks5(name, host, port, node)
    elif node.Type == ProxyType.HTTP:
        return f"{name} = http, {host}, {port}" + (f", username={node.Username}, password={pw}" if node.Username else "") + f", tls={'true' if node.TLSSecure else 'false'}"
    elif node.Type == ProxyType.HTTPS:
        return f"{name} = https, {host}, {port}, {node.Username}, {pw}"
    elif node.Type == ProxyType.Snell:
        return _surge_snell(name, host, port, node)
    elif node.Type == ProxyType.Hysteria2:
        return _surge_hysteria2(name, host, port, node)
    elif node.Type == ProxyType.AnyTLS:
        return _surge_anytls(name, host, port, node)
    elif node.Type == ProxyType.VLESS:
        return _surge_vless(name, host, port, node)
    elif node.Type == ProxyType.TUIC:
        return f"{name} = tuic, {host}, {port}, token={pw}" + (f", sni={node.ServerName}" if node.ServerName else "")
    elif node.Type == ProxyType.WireGuard:
        section = node.Remark[:8] if node.Remark else 'wg'
        return f"{name} = wireguard, section-name={section}" + (f", test-url={node.TestUrl}" if node.TestUrl else "")
    return None


def _fmt_bool(val): return str(val).lower() if val is not None else None
def _sni(node): return node.SNI or node.ServerName or ''

def _surge_vmess(name, host, port, node):
    proxy = f"{name} = vmess, {host}, {port}, username={node.UserId}"
    if node.TransferProtocol == 'ws':
        proxy += f", ws=true, ws-path={node.Path or '/'}"
        if node.Host: proxy += f", ws-headers=Host:{node.Host}"
    if node.TLSStr == 'tls':
        proxy += ", tls=true"
        sni = _sni(node)
        if sni: proxy += f", sni={sni}"
    if node.AllowInsecure is not None: proxy += f", skip-cert-verify={_fmt_bool(node.AllowInsecure)}"
    return proxy

def _surge_trojan(name, host, port, node):
    sni = node.ServerName or node.Host or host
    proxy = f"{name} = trojan, {host}, {port}, password={node.Password}"
    if sni: proxy += f", sni={sni}"
    if node.TransferProtocol == 'ws':
        proxy += f", ws=true, ws-path={node.Path or '/'}"
        if node.Host: proxy += f", ws-headers=Host:{node.Host}"
    if node.AllowInsecure is not None: proxy += f", skip-cert-verify={_fmt_bool(node.AllowInsecure)}"
    return proxy

def _surge_socks5(name, host, port, node):
    proxy = f"{name} = socks5, {host}, {port}"
    if node.Username: proxy += f", username={node.Username}"
    if node.Password: proxy += f", password={node.Password}"
    return proxy

def _surge_snell(name, host, port, node):
    proxy = f"{name} = snell, {host}, {port}, psk={node.Password}"
    if node.OBFS:
        proxy += f", obfs={node.OBFS}"
        if node.Host: proxy += f", obfs-host={node.Host}"
    if node.SnellVersion: proxy += f", version={node.SnellVersion}"
    return proxy

def _surge_hysteria2(name, host, port, node):
    proxy = f"{name} = hysteria2, {host}, {port}, password={node.Password}"
    if node.DownMbps: proxy += f", download-bandwidth={node.DownMbps}"
    if node.ServerName: proxy += f", sni={node.ServerName}"
    if node.AllowInsecure is not None: proxy += f", skip-cert-verify={_fmt_bool(node.AllowInsecure)}"
    fp = node.Fingerprint or ''
    if fp and len(fp) == 64 and all(c in '0123456789abcdefABCDEF' for c in fp):
        proxy += f", server-cert-fingerprint-sha256={fp}"
    if node.Ports: proxy += f", port-hopping={node.Ports}"
    return proxy

def _surge_anytls(name, host, port, node):
    sni = node.SNI or node.ServerName or ''
    proxy = f"{name} = anytls, {host}, {port}, password={node.Password}"
    if sni: proxy += f", sni={sni}"
    if node.AllowInsecure is not None: proxy += f", skip-cert-verify={_fmt_bool(node.AllowInsecure)}"
    fp = node.Fingerprint or ''
    if fp and len(fp) == 64 and all(c in '0123456789abcdefABCDEF' for c in fp):
        proxy += f", server-cert-fingerprint-sha256={fp}"
    return proxy

def _surge_vless(name, host, port, node):
    proxy = f"{name} = vless, {host}, {port}, username={node.UserId}"
    if node.TransferProtocol == 'ws':
        proxy += f", ws=true, ws-path={node.Path or '/'}"
        if node.Host: proxy += f", ws-headers=Host:{node.Host}"
    if node.TLSStr:
        proxy += ", tls=true"
        if node.ServerName: proxy += f", sni={node.ServerName}"
    return proxy


# Re-export for backward compatibility
proxy_to_loon = proxy_to_surge
proxy_to_quan = proxy_to_surge
proxy_to_surfboard = proxy_to_surge

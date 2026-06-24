"""Subscription export generators for all target formats.

Ported from generator/config/subexport.cpp.

Supported output formats:
- Clash / ClashR
- Surge (v2-v5)
- Quantumult / Quantumult X
- Loon
- SS / SSR / SSD / SS Android
- V2Ray / Trojan
- Sing-box
- Mellow
- Surfboard
- Mixed (standard subscription)
"""

import re
import json
import yaml
from typing import List, Optional, Dict, Any
from copy import deepcopy

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..config.settings import (
    Settings, global_settings, RegexMatchConfig, ProxyGroupConfig,
    ProxyGroupType, BalanceStrategy, RulesetConfig, RulesetContent,
    RULESET_SURGE, RULESET_QUANX, RULESET_CLASH_DOMAIN,
    RULESET_CLASH_IPCIDR, RULESET_CLASH_CLASSICAL
)
from ..utils.base64_util import base64_encode, url_safe_base64_encode
from ..utils.url_util import url_encode, url_decode
from ..utils.string_util import (
    split, starts_with, ends_with, trim, join, replace_all,
    replace_all_distinct, str_find, reg_match, reg_find, reg_replace,
    to_int, count_least, is_link, file_exist, file_get
)
from ..utils.logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_VERBOSE
from ..parser.subparser import (
    SS_CIPHERS, SSR_CIPHERS, explode_sub, explode_clash_sub,
    add_nodes as parser_add_nodes
)
from .ruleconvert import convert_ruleset


# ==================== Node Manipulation ====================

def apply_rename(remark: str, rename_list: List[RegexMatchConfig]) -> str:
    """Apply rename rules (regex substitutions) to a remark."""
    for rule in rename_list:
        if rule.Script:
            # Script-based rename - simplified: treat as regex replace pair
            # Format: match::replace (similar to old subconverter)
            if '::' in rule.Script:
                m, r = rule.Script.split('::', 1)
                remark = re.sub(m, r, remark)
            continue
        if rule.Match:
            try:
                remark = re.sub(rule.Match, rule.Replace, remark)
            except re.error:
                pass
    return remark


def apply_emoji(remark: str, emoji_list: List[RegexMatchConfig],
                add_emoji: bool, remove_emoji: bool) -> str:
    """Apply emoji rules to a remark."""
    if not add_emoji:
        return remark
    if remove_emoji:
        # Remove existing emojis
        remark = re.sub(r'[\U0001F300-\U0001F9FF\u2600-\u27BF\u2B50★⚡🔰🎯🛡️🚀]+\s*', '', remark)

    for rule in emoji_list:
        if rule.Script:
            if '::' in rule.Script:
                m, r = rule.Script.split('::', 1)
                remark = re.sub(m, r, remark)
            continue
        if rule.Match and re.search(rule.Match, remark):
            remark = rule.Replace + remark
            break

    return remark


def preprocess_nodes(nodes: List[Proxy], settings: 'ExtraSettings'):
    """Pre-process nodes: apply renames, emojis, filters, sorting."""
    # Apply renames
    for node in nodes:
        node.Remark = apply_rename(node.Remark, settings.rename_list)

    # Apply emoji
    if settings.add_emoji:
        for node in nodes:
            node.Remark = apply_emoji(
                node.Remark, settings.emoji_list,
                settings.add_emoji, settings.remove_emoji
            )

    # Append type
    if settings.append_proxy_type:
        for node in nodes:
            type_str = str(node.Type)
            if not ends_with(node.Remark, f"|{type_str}"):
                node.Remark += f"|{type_str}"

    # Sort
    if settings.sort_flag and nodes:
        nodes.sort(key=lambda n: n.Remark)

    # Filter deprecated
    if settings.filter_deprecated:
        nodes[:] = [n for n in nodes if n.Type != ProxyType.Unknown]

    # Assign node IDs
    for i, node in enumerate(nodes):
        node.Id = i


# ==================== Clash Generator ====================

def proxy_to_clash(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List[RulesetContent],
                   extra_groups: List[ProxyGroupConfig],
                   clash_r: bool = False,
                   settings: 'ExtraSettings' = None) -> str:
    """Generate Clash configuration."""
    config = yaml.safe_load(base_conf) if base_conf else {}
    if not isinstance(config, dict):
        config = {}

    # Generate proxies
    proxy_list = []
    for node in nodes:
        proxy = _clash_proxy(node, clash_r)
        if proxy:
            proxy_list.append(proxy)
    config['proxies'] = proxy_list

    # Generate proxy groups
    _add_clash_proxy_groups(config, nodes, extra_groups, settings)

    # Handle rules
    if settings and settings.enable_rule_generator and ruleset_content:
        _render_clash_rules(config, ruleset_content, settings)

    return yaml.dump(config, allow_unicode=True, default_flow_style=False,
                     sort_keys=False, width=120)


def _clash_proxy(node: Proxy, clash_r: bool = False) -> Optional[Dict]:
    """Convert a single Proxy node to Clash format."""
    name = node.Remark or f"{node.Hostname}:{node.Port}"
    p = {'name': name, 'server': node.Hostname, 'port': node.Port}

    if node.UDP is not None:
        p['udp'] = node.UDP
    if node.TCPFastOpen is not None:
        p['tfo'] = node.TCPFastOpen
    if node.AllowInsecure is not None:
        p['skip-cert-verify'] = node.AllowInsecure

    if node.Type == ProxyType.Shadowsocks:
        p['type'] = 'ss'
        p['cipher'] = node.EncryptMethod
        p['password'] = node.Password
        if node.Plugin:
            p['plugin'] = node.Plugin
        if node.PluginOption:
            p['plugin-opts'] = {'mode': node.PluginOption, 'host': node.Host}
    elif node.Type == ProxyType.ShadowsocksR:
        p['type'] = 'ssr'
        p['cipher'] = node.EncryptMethod
        p['password'] = node.Password
        p['protocol'] = node.Protocol
        p['obfs'] = node.OBFS
        if node.ProtocolParam:
            p['protocol-param'] = node.ProtocolParam
        if node.OBFSParam:
            p['obfs-param'] = node.OBFSParam
    elif node.Type == ProxyType.VMess:
        p['type'] = 'vmess'
        p['uuid'] = node.UserId
        p['alterId'] = node.AlterId
        p['cipher'] = node.EncryptMethod or 'auto'
        if node.TransferProtocol and node.TransferProtocol != 'tcp':
            p['network'] = node.TransferProtocol
        if node.Path:
            p['ws-path'] = node.Path
            p['ws-opts'] = p.get('ws-opts', {})
            if node.Host:
                p['ws-opts']['headers'] = {'Host': node.Host}
        if node.TLSStr:
            p['tls'] = True
        if node.ServerName:
            p['servername'] = node.ServerName
        if node.Fingerprint:
            p['fp'] = node.Fingerprint
    elif node.Type == ProxyType.Trojan:
        p['type'] = 'trojan'
        p['password'] = node.Password
        if node.ServerName:
            p['sni'] = node.ServerName
        if node.TransferProtocol and node.TransferProtocol != 'tcp':
            p['network'] = node.TransferProtocol
        if node.Path:
            p['ws-path'] = node.Path
            if node.Host:
                p['ws-opts'] = {'headers': {'Host': node.Host}}
    elif node.Type == ProxyType.HTTP:
        p['type'] = 'http'
        p['username'] = node.Username
        p['password'] = node.Password
        if node.TLSSecure:
            p['tls'] = True
    elif node.Type == ProxyType.SOCKS5:
        p['type'] = 'socks5'
        p['username'] = node.Username
        p['password'] = node.Password
    elif node.Type == ProxyType.VLESS:
        p['type'] = 'vless'
        p['uuid'] = node.UserId
        if node.TransferProtocol and node.TransferProtocol != 'tcp':
            p['network'] = node.TransferProtocol
        if node.Path:
            p['ws-path'] = node.Path
        if node.TLSStr == 'reality':
            p['tls'] = True
            p['reality-opts'] = {'public-key': node.PublicKey, 'short-id': node.ShortId}
            if node.Fingerprint:
                p['reality-opts']['fingerprint'] = node.Fingerprint
            if node.ServerName:
                p['servername'] = node.ServerName
        elif node.TLSStr:
            p['tls'] = True
            if node.ServerName:
                p['servername'] = node.ServerName
        if node.Flow:
            p['flow'] = node.Flow
    elif node.Type == ProxyType.Hysteria:
        p['type'] = 'hysteria'
        p['auth_str'] = node.AuthStr
        p['sni'] = node.ServerName
        if node.Host:
            p['host'] = node.Host
        if node.UpMbps:
            p['up'] = node.UpMbps
        if node.DownMbps:
            p['down'] = node.DownMbps
        if node.Alpn:
            p['alpn'] = [node.Alpn]
    elif node.Type == ProxyType.Hysteria2:
        p['type'] = 'hysteria2'
        p['password'] = node.Password
        p['sni'] = node.ServerName
        if node.OBFSPassword:
            p['obfs'] = node.OBFSParam
            p['obfs-password'] = node.OBFSPassword
        if node.UpMbps:
            p['up'] = node.UpMbps
        if node.DownMbps:
            p['down'] = node.DownMbps
    elif node.Type == ProxyType.TUIC:
        p['type'] = 'tuic'
        p['uuid'] = node.UserId
        p['password'] = node.Password
        p['sni'] = node.ServerName
        if node.CongestionControl:
            p['congestion-controller'] = node.CongestionControl
        if node.Alpn:
            p['alpn'] = [node.Alpn]
    elif node.Type == ProxyType.AnyTLS:
        p['type'] = 'anytls'
        p['password'] = node.Password
        if node.ServerName:
            p['servername'] = node.ServerName
        if node.TransferProtocol and node.TransferProtocol != 'tcp':
            p['network'] = node.TransferProtocol
    elif node.Type == ProxyType.Mieru:
        p['type'] = 'mieru'
        p['password'] = node.Password
        if node.Username:
            p['username'] = node.Username
    else:
        return None

    return p


def _add_clash_proxy_groups(config: dict, nodes: List[Proxy],
                            extra_groups: List[ProxyGroupConfig],
                            settings: 'ExtraSettings'):
    """Add proxy groups to Clash config."""
    groups = list(extra_groups) if extra_groups else []

    # Add default select group if not present
    if not any(g.Name == 'Proxy' or g.Name == '🚀 Proxy' for g in groups):
        default_group = ProxyGroupConfig(
            Name='Proxy',
            Type=ProxyGroupType.Select,
            Proxies=[n.Remark for n in nodes if n.Remark]
        )
        groups.insert(0, default_group)

    config['proxy-groups'] = []
    for g in groups:
        group = {
            'name': g.Name,
            'type': str(g.Type)
        }
        if g.Proxies:
            group['proxies'] = g.Proxies
        if g.UsingProvider:
            group['use'] = g.UsingProvider
        if g.Url:
            group['url'] = g.Url
        if g.Interval:
            group['interval'] = g.Interval
        if g.Timeout:
            group['timeout'] = g.Timeout
        if g.Tolerance:
            group['tolerance'] = g.Tolerance
        if g.Lazy is not None:
            group['lazy'] = g.Lazy
        config['proxy-groups'].append(group)


def _render_clash_rules(config: dict, ruleset_content: List[RulesetContent],
                        settings: 'ExtraSettings'):
    """Render rules for Clash config."""
    rules = []
    for rc in ruleset_content:
        content = rc.rule_content or ""
        if not content:
            continue
        converted = convert_ruleset(content, rc.rule_type or RULESET_SURGE)
        for line in converted.strip().split('\n'):
            line = trim(line)
            if not line or line[0] in (';', '#') or line.startswith('//'):
                continue
            if count_least(line, ',', 2):
                rules.append(line)
            else:
                rules.append(f"{trim(line)},{rc.rule_group}")

    if rules:
        config['rules'] = rules


# ==================== Surge Generator ====================

def proxy_to_surge(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List[RulesetContent],
                   extra_groups: List[ProxyGroupConfig],
                   surge_ver: int, settings: 'ExtraSettings') -> str:
    """Generate Surge configuration."""
    result = []

    if base_conf:
        result.append(base_conf)

    # Generate proxy list
    result.append("[Proxy]")
    for node in nodes:
        line = _surge_proxy(node)
        if line:
            result.append(line)

    # Generate proxy groups
    result.append("[Proxy Group]")
    all_remark_names = [n.Remark for n in nodes if n.Remark]

    for g in extra_groups:
        proxies = []
        used_in_this_group = set()
        for rule in g.Proxies:
            if rule == '.*':
                for r in all_remark_names:
                    if r not in used_in_this_group:
                        proxies.append(r)
                        used_in_this_group.add(r)
            elif rule.startswith('!!GROUP='):
                target_group = rule[8:]
                for node in nodes:
                    if node.Group == target_group and node.Remark not in used_in_this_group:
                        proxies.append(node.Remark)
                        used_in_this_group.add(node.Remark)
            elif rule == 'DIRECT' or rule == 'REJECT' or rule == 'REJECT-TINYGIF':
                if rule not in used_in_this_group:
                    proxies.append(rule)
                    used_in_this_group.add(rule)
            else:
                # Try as regex pattern to match node remarks
                import re
                try:
                    pattern = re.compile(rule)
                    matched_any = False
                    for node in nodes:
                        if node.Remark and pattern.search(node.Remark):
                            if node.Remark not in used_in_this_group:
                                proxies.append(node.Remark)
                                used_in_this_group.add(node.Remark)
                                matched_any = True
                    if not matched_any:
                        # Treat as literal proxy/group name if no regex match
                        if rule not in used_in_this_group:
                            proxies.append(rule)
                            used_in_this_group.add(rule)
                except re.error:
                    # Not a valid regex, treat as literal name
                    if rule not in used_in_this_group:
                        proxies.append(rule)
                        used_in_this_group.add(rule)

        if not proxies:
            continue

        proxies_str = ', '.join(proxies)
        group_line = f"{g.Name} = {str(g.Type)}, {proxies_str}"
        if g.Url:
            group_line += f", url = {g.Url}, interval = {g.Interval}"
        result.append(group_line)

    # Generate rules
    if ruleset_content:
        result.append("[Rule]")
        for rc in ruleset_content:
            content = rc.rule_content or ""
            if not content:
                continue

            # Check if this ruleset came from a remote URL → use RULE-SET format
            rule_path = rc.rule_path or ""
            if rule_path.startswith('http://') or rule_path.startswith('https://'):
                interval = rc.update_interval or 86400
                result.append(f'RULE-SET,{rule_path},"{rc.rule_group}",update-interval={interval}')
                continue

            # Check if it's an inline rule (GEOIP, FINAL, etc.)
            if rule_path.startswith('inline:') or content.startswith('GEOIP') or content.startswith('FINAL'):
                rule_text = content
                if rule_text == 'FINAL':
                    rule_text = 'MATCH'
                result.append(f"{rule_text},{rc.rule_group}")
                continue

            # Local ruleset → expand inline
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


def _surge_proxy(node: Proxy) -> Optional[str]:
    """Convert proxy node to Surge format line. Matches original subconverter C++ format."""
    name = node.Remark or f"{node.Hostname}:{node.Port}"
    host = node.Hostname
    port = str(node.Port)
    password = node.Password
    username = node.Username

    if node.Type == ProxyType.Shadowsocks:
        return f"{name} = ss, {host}, {port}, encrypt-method={node.EncryptMethod}, password={password}"

    elif node.Type == ProxyType.VMess:
        proxy = f"{name} = vmess, {host}, {port}, username={node.UserId}"
        if node.TransferProtocol == 'ws':
            proxy += f", ws=true, ws-path={node.Path or '/'}"
            if node.Host:
                proxy += f", ws-headers=Host:{node.Host}"
        if node.TLSStr == 'tls':
            proxy += ", tls=true"
            sni = node.ServerName or node.SNI or ''
            if sni:
                proxy += f", sni={sni}"
        if node.AllowInsecure is not None:
            proxy += f", skip-cert-verify={str(node.AllowInsecure).lower()}"
        return proxy

    elif node.Type == ProxyType.ShadowsocksR:
        # SSR in Surge uses custom module
        return f"{name} = custom, {host}, {port}, {node.EncryptMethod}, {password}, https://raw.githubusercontent.com/ConnersHua/SSRouter/master/SSR.module"

    elif node.Type == ProxyType.Trojan:
        sni = node.ServerName or node.Host or host
        proxy = f"{name} = trojan, {host}, {port}, password={password}"
        if sni:
            proxy += f", sni={sni}"
        if node.TransferProtocol == 'ws':
            proxy += f", ws=true, ws-path={node.Path or '/'}"
            if node.Host:
                proxy += f", ws-headers=Host:{node.Host}"
        if node.AllowInsecure is not None:
            proxy += f", skip-cert-verify={str(node.AllowInsecure).lower()}"
        return proxy

    elif node.Type == ProxyType.SOCKS5:
        proxy = f"{name} = socks5, {host}, {port}"
        if username:
            proxy += f", username={username}"
        if password:
            proxy += f", password={password}"
        return proxy

    elif node.Type == ProxyType.HTTP:
        proxy = f"{name} = http, {host}, {port}"
        if username:
            proxy += f", username={username}"
        if password:
            proxy += f", password={password}"
        proxy += f", tls={'true' if node.TLSSecure else 'false'}"
        return proxy

    elif node.Type == ProxyType.HTTPS:
        proxy = f"{name} = https, {host}, {port}, {username}, {password}"
        if node.AllowInsecure is not None:
            proxy += f", skip-cert-verify={str(node.AllowInsecure).lower()}"
        return proxy

    elif node.Type == ProxyType.Snell:
        proxy = f"{name} = snell, {host}, {port}, psk={password}"
        if node.OBFS:
            proxy += f", obfs={node.OBFS}"
            if node.Host:
                proxy += f", obfs-host={node.Host}"
        if node.SnellVersion:
            proxy += f", version={node.SnellVersion}"
        return proxy

    elif node.Type == ProxyType.Hysteria2:
        proxy = f"{name} = hysteria2, {host}, {port}, password={password}"
        if node.DownMbps:
            proxy += f", download-bandwidth={node.DownMbps}"
        if node.ServerName:
            proxy += f", sni={node.ServerName}"
        if node.AllowInsecure is not None:
            proxy += f", skip-cert-verify={str(node.AllowInsecure).lower()}"
        fp = node.Fingerprint or ''
        if fp and len(fp) == 64 and all(c in '0123456789abcdefABCDEF' for c in fp):
            proxy += f", server-cert-fingerprint-sha256={fp}"
        if node.Ports:
            proxy += f", port-hopping={node.Ports}"
        return proxy

    elif node.Type == ProxyType.AnyTLS:
        sni = node.SNI or node.ServerName or ''
        proxy = f"{name} = anytls, {host}, {port}, password={password}"
        if sni:
            proxy += f", sni={sni}"
        if node.AllowInsecure is not None:
            proxy += f", skip-cert-verify={str(node.AllowInsecure).lower()}"
        # Only output fingerprint if it looks like a real SHA256 hash (64 hex chars)
        fp = node.Fingerprint or ''
        if fp and len(fp) == 64 and all(c in '0123456789abcdefABCDEF' for c in fp):
            proxy += f", server-cert-fingerprint-sha256={fp}"
        return proxy

    elif node.Type == ProxyType.VLESS:
        proxy = f"{name} = vless, {host}, {port}, username={node.UserId}"
        if node.TransferProtocol == 'ws':
            proxy += f", ws=true, ws-path={node.Path or '/'}"
            if node.Host:
                proxy += f", ws-headers=Host:{node.Host}"
        if node.TLSStr:
            proxy += f", tls=true"
            if node.ServerName:
                proxy += f", sni={node.ServerName}"
        return proxy

    elif node.Type == ProxyType.TUIC:
        proxy = f"{name} = tuic, {host}, {port}, token={password}, username={node.UserId or node.UserId}"
        if node.ServerName:
            proxy += f", sni={node.ServerName}"
        if node.Alpn:
            proxy += f", alpn={node.Alpn}"
        return proxy

    elif node.Type == ProxyType.WireGuard:
        from ..utils.string_util import random_str
        section = node.Remark[:8] if node.Remark else 'wg'
        proxy = f"{name} = wireguard, section-name={section}"
        if node.TestUrl:
            proxy += f", test-url={node.TestUrl}"
        return proxy

    return None


# ==================== Quantumult X Generator ====================

def proxy_to_quanx(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List[RulesetContent],
                   extra_groups: List[ProxyGroupConfig],
                   settings: 'ExtraSettings') -> str:
    """Generate Quantumult X configuration."""
    result = []

    if base_conf:
        result.append(base_conf)

    # Server section
    result.append("[server_local]")
    for node in nodes:
        line = _quanx_proxy(node)
        if line:
            result.append(line)

    # Policy section
    result.append("[policy]")
    for g in extra_groups:
        proxies_str = ', '.join(g.Proxies)
        result.append(f"{'static' if g.Type == ProxyGroupType.Select else 'available'}={g.Name}, {proxies_str}")

    # Filter section
    if ruleset_content:
        result.append("[filter_local]")
        for rc in ruleset_content:
            content = rc.rule_content or ""
            if not content:
                continue
            converted = convert_ruleset(content, rc.rule_type or RULESET_SURGE)
            for line in converted.strip().split('\n'):
                line = trim(line)
                if not line or line[0] in (';', '#') or line.startswith('//'):
                    continue
                result.append(f"{line},{rc.rule_group}")

    return '\n'.join(result) + '\n'


def _quanx_proxy(node: Proxy) -> Optional[str]:
    """Convert proxy node to Quantumult X format."""
    name = node.Remark or f"{node.Hostname}:{node.Port}"

    if node.Type == ProxyType.Shadowsocks:
        return f"shadowsocks={node.Hostname}:{node.Port}, method={node.EncryptMethod}, password={node.Password}, fast-open=false, udp-relay=false, tag={name}"
    elif node.Type == ProxyType.VMess:
        ws = (node.TransferProtocol == 'ws')
        tls = node.TLSStr == 'tls'
        opts = f", obfs={'wss' if ws and tls else 'ws' if ws else 'over-tls' if tls else 'none'}"
        if node.Path:
            opts += f", obfs-host={node.Host}"
            opts += f", obfs-uri={node.Path}"
        if node.TLSStr:
            opts += f", tls13={node.TLS13 or False}"
        return f"vmess={node.Hostname}:{node.Port}, method={node.EncryptMethod}, password={node.UserId}{opts}, tag={name}"
    elif node.Type == ProxyType.Trojan:
        ws = (node.TransferProtocol == 'ws')
        tls = node.TLSStr == 'tls'
        return f"trojan={node.Hostname}:{node.Port}, password={node.Password}, over-tls={'true' if tls else 'false'}, tls-host={node.ServerName or node.Hostname}, fast-open=false, udp-relay=false, tag={name}"
    elif node.Type == ProxyType.AnyTLS:
        return f"anytls={node.Hostname}:{node.Port}, password={node.Password}, sni={node.ServerName or node.Hostname}, fast-open=false, udp-relay=false, tag={name}"

    return None


# ==================== Simple Subscription Generator ====================

def proxy_to_single(nodes: List[Proxy], types: int,
                    settings: 'ExtraSettings') -> str:
    """
    Generate simple subscription (SS/SSR/V2Ray/Trojan/VLESS links).

    types is a bitmask:
    1  = SS
    2  = SSR
    4  = V2Ray/VMess
    8  = Trojan
    16 = VLESS
    32 = Hysteria/Hysteria2
    63 = Mixed (all)
    """
    import base64 as b64

    result_lines = []

    for node in nodes:
        link = None
        if node.Type == ProxyType.Shadowsocks and (types & 1):
            link = _build_ss_link(node)
        elif node.Type == ProxyType.ShadowsocksR and (types & 2):
            link = _build_ssr_link(node)
        elif node.Type == ProxyType.VMess and (types & 4):
            link = _build_vmess_link(node)
        elif node.Type == ProxyType.Trojan and (types & 8):
            link = _build_trojan_link(node)
        elif node.Type == ProxyType.VLESS and (types & 16):
            link = _build_vless_link(node)
        elif node.Type in (ProxyType.Hysteria, ProxyType.Hysteria2) and (types & 32):
            link = _build_hysteria_link(node)
        elif types == 63:  # Mixed mode
            link = _build_any_link(node)

        if link:
            result_lines.append(link)

    content = '\n'.join(result_lines)
    return b64.b64encode(content.encode()).decode()


def _build_ss_link(node: Proxy) -> str:
    """Build SS link from proxy node."""
    userinfo = f"{node.EncryptMethod}:{node.Password}@"
    encoded = base64_encode(userinfo[:-1] if userinfo.endswith('@') else userinfo)
    link = f"ss://{encoded}{node.Hostname}:{node.Port}"

    params = []
    if node.Plugin:
        params.append(f"plugin={url_encode(node.Plugin)}")
    if params:
        link += '?' + '&'.join(params)

    if node.Remark:
        link += f"#{url_encode(node.Remark)}"
    return link


def _build_ssr_link(node: Proxy) -> str:
    """Build SSR link from proxy node."""
    password_b64 = base64_encode(node.Password).rstrip('=')
    main = f"{node.Hostname}:{node.Port}:{node.Protocol}:{node.EncryptMethod}:{node.OBFS}:{password_b64}"

    params = []
    if node.OBFSParam:
        params.append(f"obfsparam={url_encode(base64_encode(node.OBFSParam))}")
    if node.ProtocolParam:
        params.append(f"protoparam={url_encode(base64_encode(node.ProtocolParam))}")
    if node.Remark and node.Remark != node.Hostname:
        params.append(f"remarks={url_encode(base64_encode(node.Remark))}")
    if node.Group:
        params.append(f"group={url_encode(base64_encode(node.Group))}")

    if params:
        main += '/?' + '&'.join(params)

    encoded = base64_encode(main)
    return f"ssr://{encoded}"


def _build_vmess_link(node: Proxy) -> str:
    """Build VMess link from proxy node."""
    data = {
        'v': '2',
        'ps': node.Remark or node.Hostname,
        'add': node.Hostname,
        'port': str(node.Port),
        'id': node.UserId,
        'aid': str(node.AlterId),
        'net': node.TransferProtocol or 'tcp',
        'type': 'none',
        'host': node.Host or '',
        'path': node.Path or '',
        'tls': node.TLSStr or '',
    }
    if node.ServerName:
        data['sni'] = node.ServerName

    b64 = base64_encode(json.dumps(data))
    return f"vmess://{b64}"


def _build_trojan_link(node: Proxy) -> str:
    """Build Trojan link from proxy node."""
    link = f"trojan://{url_encode(node.Password)}@{node.Hostname}:{node.Port}"

    params = []
    if node.ServerName and node.ServerName != node.Hostname:
        params.append(f"sni={url_encode(node.ServerName)}")
    elif node.Hostname:
        params.append(f"sni={url_encode(node.Hostname)}")
    if node.TransferProtocol and node.TransferProtocol != 'tcp':
        params.append(f"type={node.TransferProtocol}")
    if node.Host:
        params.append(f"host={url_encode(node.Host)}")
    if node.Path:
        params.append(f"path={url_encode(node.Path)}")
    if node.AllowInsecure is not None:
        params.append(f"allowInsecure={'1' if node.AllowInsecure else '0'}")
    if params:
        link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname:
        link += f"#{url_encode(node.Remark)}"
    return link


def _build_vless_link(node: Proxy) -> str:
    """Build VLESS link from proxy node."""
    link = f"vless://{node.UserId}@{node.Hostname}:{node.Port}"

    params = []
    if node.TransferProtocol and node.TransferProtocol != 'tcp':
        params.append(f"type={node.TransferProtocol}")
    if node.TLSStr:
        params.append(f"security={node.TLSStr}")
    if node.ServerName:
        params.append(f"sni={url_encode(node.ServerName)}")
    if node.Fingerprint:
        params.append(f"fp={node.Fingerprint}")
    if node.Flow:
        params.append(f"flow={node.Flow}")
    if params:
        link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname:
        link += f"#{url_encode(node.Remark)}"
    return link


def _build_hysteria_link(node: Proxy) -> str:
    """Build Hysteria/Hysteria2 link from proxy node."""
    if node.Type == ProxyType.Hysteria2:
        link = f"hysteria2://{url_encode(node.Password)}@{node.Hostname}:{node.Port}"
    else:
        link = f"hysteria://{node.Hostname}:{node.Port}"

    params = []
    if node.ServerName and node.ServerName != node.Hostname:
        params.append(f"sni={url_encode(node.ServerName)}")
    if node.Alpn:
        params.append(f"alpn={node.Alpn}")
    if node.OBFSParam:
        params.append(f"obfs={node.OBFSParam}")
    if params:
        link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname:
        link += f"#{url_encode(node.Remark)}"
    return link


def _build_any_link(node: Proxy) -> str:
    """Build appropriate link based on proxy type."""
    builders = {
        ProxyType.Shadowsocks: _build_ss_link,
        ProxyType.ShadowsocksR: _build_ssr_link,
        ProxyType.VMess: _build_vmess_link,
        ProxyType.Trojan: _build_trojan_link,
        ProxyType.VLESS: _build_vless_link,
        ProxyType.Hysteria: _build_hysteria_link,
        ProxyType.Hysteria2: _build_hysteria_link,
        ProxyType.AnyTLS: _build_trojan_link,  # AnyTLS uses trojan-like URL format
    }
    builder = builders.get(node.Type)
    if builder:
        return builder(node)
    return None


# ==================== Sing-box Generator ====================

def proxy_to_singbox(nodes: List[Proxy], base_conf: str,
                     ruleset_content: List[RulesetContent],
                     extra_groups: List[ProxyGroupConfig],
                     settings: 'ExtraSettings') -> str:
    """Generate sing-box configuration."""
    config = {}
    if base_conf:
        try:
            config = json.loads(base_conf)
        except json.JSONDecodeError:
            config = {}

    # Outbounds
    outbounds = []
    for node in nodes:
        outbound = _singbox_proxy(node)
        if outbound:
            outbounds.append(outbound)

    config['outbounds'] = outbounds or config.get('outbounds', [])

    # Add selector
    if outbounds:
        selector = {
            "type": "selector",
            "tag": "proxy",
            "outbounds": [o['tag'] for o in outbounds if 'tag' in o]
        }
        # Insert at beginning
        all_outbounds = config.get('outbounds', [])
        all_outbounds.insert(0, selector)
        config['outbounds'] = all_outbounds

    return json.dumps(config, indent=2, ensure_ascii=False)


def _singbox_proxy(node: Proxy) -> Optional[Dict]:
    """Convert proxy node to sing-box format."""
    tag = node.Remark or f"{node.Hostname}:{node.Port}"
    out = {'tag': tag, 'server': node.Hostname, 'server_port': node.Port}

    if node.Type == ProxyType.Shadowsocks:
        out['type'] = 'shadowsocks'
        out['method'] = node.EncryptMethod
        out['password'] = node.Password
        if node.Plugin:
            out['plugin'] = node.Plugin
    elif node.Type == ProxyType.VMess:
        out['type'] = 'vmess'
        out['uuid'] = node.UserId
        out['security'] = node.EncryptMethod or 'auto'
        if node.TransferProtocol and node.TransferProtocol != 'tcp':
            if node.TransferProtocol == 'ws':
                out['transport'] = {
                    'type': 'ws',
                    'path': node.Path or '/',
                    'headers': {'Host': node.Host or node.Hostname}
                }
        if node.TLSStr:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName or node.Hostname}
    elif node.Type == ProxyType.Trojan:
        out['type'] = 'trojan'
        out['password'] = node.Password
        if node.ServerName:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.Hysteria:
        out['type'] = 'hysteria'
        out['auth_str'] = node.AuthStr
        out['up_mbps'] = int(node.UpMbps) if node.UpMbps and node.UpMbps.isdigit() else 50
        out['down_mbps'] = int(node.DownMbps) if node.DownMbps and node.DownMbps.isdigit() else 100
        if node.ServerName:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.Hysteria2:
        out['type'] = 'hysteria2'
        out['password'] = node.Password
        if node.ServerName:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.TUIC:
        out['type'] = 'tuic'
        out['uuid'] = node.UserId
        out['password'] = node.Password
        if node.ServerName:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.AnyTLS:
        out['type'] = 'anytls'
        out['password'] = node.Password
        if node.ServerName:
            out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    else:
        return None

    return out


# ==================== SSD Generator ====================

def proxy_to_ssd(nodes: List[Proxy], group: str, userinfo: str,
                 settings: 'ExtraSettings') -> str:
    """Generate SSD subscription."""
    ss_nodes = [n for n in nodes if n.Type == ProxyType.Shadowsocks]
    result_lines = []

    for node in ss_nodes:
        line = f"{node.Hostname}:{node.Port}:{node.EncryptMethod}:{node.Password}"
        result_lines.append(line)

    content = '\n'.join(result_lines)
    return f"ssd://{base64_encode(content)}"


# ==================== SS Sub Generator ====================

def proxy_to_ss_sub(base_conf: str, nodes: List[Proxy],
                    settings: 'ExtraSettings') -> str:
    """Generate SS subscription (Android format)."""
    import base64 as b64

    ss_nodes = [n for n in nodes if n.Type == ProxyType.Shadowsocks]
    links = []
    for node in ss_nodes:
        link = _build_ss_link(node)
        links.append(link)

    content = '\n'.join(links)
    return b64.b64encode(content.encode()).decode()


# ==================== Quantumult Generator ====================

def proxy_to_quan(nodes: List[Proxy], base_conf: str,
                  ruleset_content: List[RulesetContent],
                  extra_groups: List[ProxyGroupConfig],
                  settings: 'ExtraSettings') -> str:
    """Generate Quantumult configuration."""
    # Quantumult uses similar format to Surge with some differences
    # For simplicity, reuse Surge format
    return proxy_to_surge(nodes, base_conf, ruleset_content, extra_groups, 2, settings)


# ==================== Loon Generator ====================

def proxy_to_loon(nodes: List[Proxy], base_conf: str,
                  ruleset_content: List[RulesetContent],
                  extra_groups: List[ProxyGroupConfig],
                  settings: 'ExtraSettings') -> str:
    """Generate Loon configuration."""
    # Loon uses similar format to Surge
    return proxy_to_surge(nodes, base_conf, ruleset_content, extra_groups, 4, settings)


# ==================== Mellow Generator ====================

def proxy_to_mellow(nodes: List[Proxy], base_conf: str,
                    ruleset_content: List[RulesetContent],
                    extra_groups: List[ProxyGroupConfig],
                    settings: 'ExtraSettings') -> str:
    """Generate Mellow configuration."""
    # Mellow is a V2Ray-based client
    result = []
    if base_conf:
        result.append(base_conf)

    for node in nodes:
        if node.Type == ProxyType.VMess:
            link = _build_vmess_link(node)
            if link:
                result.append(link)

    return '\n'.join(result) + '\n'


# ==================== ExtraSettings ====================

class ExtraSettings:
    """Extra settings for node generation, mirrors C++ extra_settings."""
    enable_rule_generator: bool = True
    overwrite_original_rules: bool = True
    rename_list: List[RegexMatchConfig] = None
    emoji_list: List[RegexMatchConfig] = None
    add_emoji: bool = False
    remove_emoji: bool = False
    append_proxy_type: bool = False
    nodelist: bool = False
    sort_flag: bool = False
    filter_deprecated: bool = False
    clash_new_field_name: bool = False
    clash_script: bool = False
    surge_ssr_path: str = ""
    managed_config_prefix: str = ""
    quanx_dev_id: str = ""
    udp: Optional[bool] = None
    tfo: Optional[bool] = None
    xudp: Optional[bool] = None
    skip_cert_verify: Optional[bool] = None
    tls13: Optional[bool] = None
    clash_classical_ruleset: bool = False
    sort_script: str = ""
    clash_proxies_style: str = "flow"
    clash_proxy_groups_style: str = "flow"
    authorized: bool = False

    def __init__(self):
        self.rename_list = []
        self.emoji_list = []

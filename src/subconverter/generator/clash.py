"""Clash configuration generator."""

from typing import List, Optional, Dict

import yaml

from ..config.models import Proxy, ProxyType
from ..config.settings import ProxyGroupConfig, ProxyGroupType
from ..utils.string_util import count_least, trim
from .common import ExtraSettings, expand_group_rules
from .ruleconvert import convert_ruleset, RULESET_SURGE


def proxy_to_clash(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List,
                   extra_groups: List[ProxyGroupConfig],
                   clash_r: bool = False,
                   settings: ExtraSettings = None) -> str:
    """Generate Clash configuration."""
    config = yaml.safe_load(base_conf) if base_conf else {}
    if not isinstance(config, dict):
        config = {}
    config.pop('Proxy', None)
    config.pop('Proxy Group', None)
    config.pop('Rule', None)

    proxy_list = [_clash_proxy(n, clash_r) for n in nodes if _clash_proxy(n, clash_r)]
    config['proxies'] = proxy_list

    _add_clash_proxy_groups(config, nodes, extra_groups, settings)

    if settings and settings.enable_rule_generator and ruleset_content:
        _render_clash_rules(config, ruleset_content, settings)

    output = yaml.dump(config, allow_unicode=True, default_flow_style=False,
                       sort_keys=False, width=200)
    return _post_process_flow(output)


# ==================== Clash Proxy Builder ====================

def _clash_proxy(node: Proxy, clash_r: bool = False) -> Optional[Dict]:
    """Convert a Proxy node to Clash dict format."""
    name = node.Remark or f"{node.Hostname}:{node.Port}"
    p = {'name': name, 'server': node.Hostname, 'port': node.Port}
    if node.UDP is not None:
        p['udp'] = node.UDP
    if node.TCPFastOpen is not None:
        p['tfo'] = node.TCPFastOpen
    if node.AllowInsecure is not None:
        p['skip-cert-verify'] = node.AllowInsecure

    builders = {
        ProxyType.Shadowsocks: _clash_ss,
        ProxyType.ShadowsocksR: _clash_ssr,
        ProxyType.VMess: _clash_vmess,
        ProxyType.Trojan: _clash_trojan,
        ProxyType.HTTP: _clash_http,
        ProxyType.HTTPS: _clash_http,
        ProxyType.SOCKS5: _clash_socks5,
        ProxyType.VLESS: _clash_vless,
        ProxyType.Hysteria: _clash_hysteria,
        ProxyType.Hysteria2: _clash_hysteria2,
        ProxyType.TUIC: _clash_tuic,
        ProxyType.AnyTLS: _clash_anytls,
        ProxyType.Mieru: _clash_mieru,
    }
    builder = builders.get(node.Type)
    if builder:
        builder(p, node)
    else:
        return None
    return p


def _clash_ss(p, node): p.update(type='ss', cipher=node.EncryptMethod, password=node.Password)
def _clash_ssr(p, node): p.update(type='ssr', cipher=node.EncryptMethod, password=node.Password, protocol=node.Protocol, obfs=node.OBFS)
def _clash_vmess(p, node):
    p.update(type='vmess', uuid=node.UserId, alterId=node.AlterId, cipher=node.EncryptMethod or 'auto')
    if node.TransferProtocol != 'tcp': p['network'] = node.TransferProtocol
    if node.Path: p['ws-path'] = node.Path
    if node.Host: p['ws-opts'] = {'headers': {'Host': node.Host}}
    if node.TLSStr: p['tls'] = True
    if node.ServerName: p['servername'] = node.ServerName
    if node.Fingerprint: p['fp'] = node.Fingerprint
def _clash_trojan(p, node):
    p.update(type='trojan', password=node.Password)
    if node.ServerName: p['sni'] = node.ServerName
    if node.TransferProtocol != 'tcp': p['network'] = node.TransferProtocol
    if node.Path: p['ws-path'] = node.Path
    if node.Host: p['ws-opts'] = {'headers': {'Host': node.Host}}
def _clash_http(p, node): p.update(type='http', username=node.Username, password=node.Password)
def _clash_socks5(p, node): p.update(type='socks5', username=node.Username, password=node.Password)
def _clash_anytls(p, node): p.update(type='anytls', password=node.Password)
def _clash_mieru(p, node): p.update(type='mieru', password=node.Password)
def _clash_vless(p, node):
    p.update(type='vless', uuid=node.UserId)
    if node.TransferProtocol != 'tcp': p['network'] = node.TransferProtocol
def _clash_hysteria(p, node):
    p.update(type='hysteria', auth_str=node.AuthStr, sni=node.ServerName)
    if node.Host: p['host'] = node.Host
    if node.UpMbps: p['up'] = node.UpMbps
    if node.DownMbps: p['down'] = node.DownMbps
    if node.Alpn: p['alpn'] = [node.Alpn]
def _clash_hysteria2(p, node):
    p.update(type='hysteria2', password=node.Password, sni=node.ServerName)
    if node.OBFSPassword: p['obfs'] = node.OBFSParam; p['obfs-password'] = node.OBFSPassword
    if node.UpMbps: p['up'] = node.UpMbps
    if node.DownMbps: p['down'] = node.DownMbps
def _clash_tuic(p, node):
    p.update(type='tuic', uuid=node.UserId, password=node.Password, sni=node.ServerName)
    if node.CongestionControl: p['congestion-controller'] = node.CongestionControl
    if node.Alpn: p['alpn'] = [node.Alpn]


# ==================== Clash Proxy Groups ====================

def _add_clash_proxy_groups(config, nodes, extra_groups, settings):
    groups = list(extra_groups) if extra_groups else []
    all_remark_names = [n.Remark for n in nodes if n.Remark]
    all_group_names = {g.Name for g in groups}

    if not groups:
        groups.insert(0, ProxyGroupConfig(
            Name='Proxy', Type=ProxyGroupType.Select,
            Proxies=list(all_remark_names)))
        all_group_names.add('Proxy')

    config['proxy-groups'] = []
    config.pop('Proxy Group', None)

    for g in groups:
        expanded = expand_group_rules(g.Proxies, nodes, all_remark_names, all_group_names)
        if not expanded:
            pass
        group = {'name': g.Name, 'type': str(g.Type), 'proxies': expanded}
        if g.UsingProvider: group['use'] = g.UsingProvider
        if g.Url: group['url'] = g.Url
        if g.Interval: group['interval'] = g.Interval
        if g.Timeout: group['timeout'] = g.Timeout
        if g.Tolerance: group['tolerance'] = g.Tolerance
        if g.Lazy is not None: group['lazy'] = g.Lazy
        config['proxy-groups'].append(group)


# ==================== Clash Rules ====================

def _render_clash_rules(config, ruleset_content, settings):
    rules = []
    rule_providers = config.get('rule-providers', {})

    for rc in ruleset_content:
        rule_path = rc.rule_path or ""

        if rule_path.startswith('http://') or rule_path.startswith('https://'):
            import hashlib
            provider_name = 'rule_' + hashlib.md5(rule_path.encode()).hexdigest()[:8]
            interval = rc.update_interval or 86400
            content = rc.rule_content or ""
            if content and 'IP-CIDR' in content[:500]:
                behavior = 'ipcidr'
            elif content and 'DOMAIN' in content[:500]:
                behavior = 'domain'
            else:
                behavior = 'classical'
            rule_providers[provider_name] = {
                'type': 'http', 'behavior': behavior, 'url': rule_path,
                'path': f'./providers/{provider_name}.yaml', 'interval': interval
            }
            rules.append(f'RULE-SET,{provider_name},{rc.rule_group}')
            continue

        if rule_path.startswith('inline:') or (rc.rule_content or '').startswith('GEOIP') \
                or (rc.rule_content or '').startswith('FINAL'):
            rule_text = (rc.rule_content or '').strip()
            if rule_text == 'FINAL': rule_text = 'MATCH'
            rules.append(f'{rule_text},{rc.rule_group}')
            continue

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

    if rule_providers:
        config['rule-providers'] = rule_providers
    if rules:
        config['rules'] = rules


# ==================== Flow Style Post-Processing ====================

def _post_process_flow(yaml_str: str) -> str:
    """Post-process YAML to convert proxies to flow style with proper quoting."""
    lines = yaml_str.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped == 'proxies:':
            result.append(line)
            i += 1
            while i < len(lines):
                if lines[i] == '': result.append(lines[i]); i += 1; continue
                if not lines[i].startswith('- '): break
                item_lines = [lines[i][2:]]
                i += 1
                while i < len(lines) and lines[i].startswith('  ') and not lines[i].startswith('- '):
                    item_lines.append(lines[i][2:]); i += 1
                parts = []
                for il in item_lines:
                    if ':' in il:
                        key, val = il.split(':', 1)
                        val = val.strip()
                        if val and any(c in val for c in '[]{}:,"\'#&*!|>%@` '):
                            escaped = val.replace('\\', '\\\\').replace('"', '\\"')
                            parts.append(f'{key}: "{escaped}"')
                        else:
                            parts.append(il)
                    else:
                        parts.append(il)
                result.append('- {' + ', '.join(parts) + '}')
            continue

        if stripped == 'rule-providers:':
            result.append(line)
            i += 1
            while i < len(lines) and lines[i].startswith('  ') and not lines[i].startswith('    '):
                name = lines[i].strip()[:-1]; i += 1
                props = []
                while i < len(lines) and lines[i].startswith('    '):
                    prop = lines[i].strip()
                    if ':' in prop:
                        key, val = prop.split(':', 1)
                        val = val.strip()
                        if val and any(c in val for c in '[]{}:,"\'#&*!|>%@` '):
                            escaped = val.replace('\\', '\\\\').replace('"', '\\"')
                            prop = f'{key}: "{escaped}"'
                    props.append(prop); i += 1
                result.append(f'  {name}: {{{', '.join(props)}}}')
            continue

        result.append(line); i += 1
    return '\n'.join(result)

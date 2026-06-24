"""Configuration file loader - ported from handler/settings.cpp.

Handles loading pref.ini, pref.toml, pref.yml, and external configs.
"""

import os
import re
import yaml
from typing import List, Dict, Any, Optional

from ..config.settings import (
    Settings, global_settings, RegexMatchConfig, ProxyGroupConfig,
    ProxyGroupType, BalanceStrategy, RulesetConfig, RulesetContent,
    RULESET_SURGE, RULESET_QUANX, RULESET_CLASH_DOMAIN,
    RULESET_CLASH_IPCIDR, RULESET_CLASH_CLASSICAL, ExternalConfig
)
from ..utils.string_util import (
    starts_with, ends_with, trim, split, join,
    is_link, file_exist, file_get, file_write, file_copy, to_int
)
from ..utils.network import web_get, parse_proxy
from ..utils.logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR


def _find_pref_file() -> Optional[str]:
    """Find the preference file (pref.ini, pref.toml, or pref.yml)."""
    for name in ["pref.toml", "pref.yml", "pref.ini"]:
        if file_exist(name):
            return name

    # Try to create from example
    for src, dst in [
        ("pref.example.toml", "pref.toml"),
        ("pref.example.yml", "pref.yml"),
        ("pref.example.ini", "pref.ini")
    ]:
        if file_exist(src):
            file_copy(src, dst)
            return dst

    return None


def read_conf(pref_path: str = None) -> Settings:
    """Read main configuration file."""
    gs = global_settings

    if pref_path:
        gs.pref_path = pref_path
    if not gs.pref_path or not file_exist(gs.pref_path):
        gs.pref_path = _find_pref_file()

    if not gs.pref_path or not file_exist(gs.pref_path):
        write_log(0, "No preference file found!", LOG_LEVEL_WARNING)
        return gs

    write_log(0, f"Loading configuration from {gs.pref_path}", LOG_LEVEL_INFO)

    content = file_get(gs.pref_path)
    if not content:
        return gs

    if gs.pref_path.endswith('.toml'):
        _read_toml_conf(content)
    elif gs.pref_path.endswith('.yml') or gs.pref_path.endswith('.yaml'):
        _read_yml_conf(content)
    else:
        _read_ini_conf(content)

    return gs


def _read_ini_conf(content: str):
    """Parse INI-style configuration."""
    gs = global_settings

    sections = _parse_ini_sections(content)

    # [common]
    common = sections.get('common', {})
    gs.api_mode = common.get('api_mode', str(gs.api_mode)).lower() != 'false'
    gs.listen_address = common.get('listen', gs.listen_address)
    gs.listen_port = int(common.get('port', str(gs.listen_port)))
    gs.default_urls = common.get('default_url', '')
    gs.insert_urls = common.get('insert_url', '')
    gs.managed_config_prefix = common.get('managed_config_prefix', '')
    gs.access_token = common.get('api_access_token', '')
    gs.base_path = common.get('base_path', gs.base_path)
    gs.proxy_config = common.get('proxy_config', '')
    gs.proxy_ruleset = common.get('proxy_ruleset', '')
    gs.proxy_subscription = common.get('proxy_subscription', '')
    gs.update_interval = int(common.get('clash_rule_refresh_interval', str(gs.update_interval)))
    gs.append_userinfo = common.get('append_userinfo', str(gs.append_userinfo)).lower() != 'false'
    gs.enable_insert = common.get('enable_insert', 'false').lower() == 'true'
    gs.prepend_insert = common.get('prepend_insert', str(gs.prepend_insert)).lower() != 'false'
    gs.write_managed_config = common.get('write_managed_config', 'false').lower() == 'true'

    # [node_pref]
    node_pref = sections.get('node_pref', {})
    gs.udp_flag = _parse_tribool(node_pref.get('udp_flag'))
    gs.tfo_flag = _parse_tribool(node_pref.get('tfo_flag'))
    gs.skip_cert_verify = _parse_tribool(node_pref.get('skip_cert_verify'))
    gs.tls13_flag = _parse_tribool(node_pref.get('tls13_flag'))
    gs.enable_sort = node_pref.get('enable_sort', 'false').lower() == 'true'
    gs.filter_deprecated = node_pref.get('filter_deprecated', 'true').lower() != 'false'
    gs.clash_use_new_field = node_pref.get('clash_use_new_field_name', 'false').lower() == 'true'
    gs.add_emoji = node_pref.get('add_emoji', 'false').lower() == 'true'
    gs.remove_emoji = node_pref.get('remove_old_emoji', 'false').lower() == 'true'

    # [server]
    server = sections.get('server', {})
    gs.clash_base = server.get('clash_rule_base', '')
    gs.surge_base = server.get('surge_rule_base', '')
    gs.surfboard_base = server.get('surfboard_rule_base', '')
    gs.quan_base = server.get('quan_rule_base', '')
    gs.quan_x_base = server.get('quanx_rule_base', '')
    gs.loon_base = server.get('loon_rule_base', '')
    gs.ss_sub_base = server.get('sssub_rule_base', '')
    gs.sing_box_base = server.get('singbox_rule_base', '')

    # [cache]
    cache = sections.get('cache', {})
    gs.cache_subscription = int(cache.get('subscription', str(gs.cache_subscription)))
    gs.cache_config = int(cache.get('config', str(gs.cache_config)))
    gs.cache_ruleset = int(cache.get('ruleset', str(gs.cache_ruleset)))
    gs.serve_cache_on_fetch_fail = cache.get('serve_stale', 'false').lower() == 'true'

    # [template]
    template = sections.get('template', {})
    for key, val in template.items():
        gs.template_vars[key] = val

    # [aliases]
    aliases = sections.get('aliases', {})
    for key, val in aliases.items():
        gs.aliases[key] = val


def _read_toml_conf(content: str):
    """Parse TOML-style configuration."""
    gs = global_settings
    try:
        import toml
        data = toml.loads(content)
    except ImportError:
        # Fall back to manual parsing
        write_log(0, "toml module not available, trying YAML-style parsing", LOG_LEVEL_WARNING)
        _read_yml_conf(content)
        return

    common = data.get('common', {})
    gs.api_mode = common.get('api_mode', gs.api_mode)
    gs.listen_address = common.get('listen', gs.listen_address)
    gs.listen_port = int(common.get('port', gs.listen_port))
    gs.default_urls = common.get('default_url', '')
    gs.insert_urls = common.get('insert_url', '')
    gs.managed_config_prefix = common.get('managed_config_prefix', '')
    gs.access_token = common.get('api_access_token', '')
    gs.base_path = common.get('base_path', gs.base_path)

    node_pref = data.get('node_pref', {})
    gs.udp_flag = node_pref.get('udp_flag')
    gs.tfo_flag = node_pref.get('tfo_flag')
    gs.skip_cert_verify = node_pref.get('skip_cert_verify')
    gs.enable_sort = node_pref.get('enable_sort', False)
    gs.filter_deprecated = node_pref.get('filter_deprecated', True)
    gs.clash_use_new_field = node_pref.get('clash_use_new_field_name', False)

    server = data.get('server', {})
    gs.clash_base = server.get('clash_rule_base', '')
    gs.surge_base = server.get('surge_rule_base', '')
    gs.sing_box_base = server.get('singbox_rule_base', '')

    cache = data.get('cache', {})
    gs.cache_subscription = cache.get('subscription', gs.cache_subscription)
    gs.cache_config = cache.get('config', gs.cache_config)
    gs.cache_ruleset = cache.get('ruleset', gs.cache_ruleset)

    template = data.get('template', {})
    for key, val in template.items():
        gs.template_vars[key] = str(val)


def _read_yml_conf(content: str):
    """Parse YAML-style configuration."""
    gs = global_settings
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return
    except yaml.YAMLError:
        return

    common = data.get('common', {})
    if common:
        gs.api_mode = common.get('api_mode', gs.api_mode)
        gs.listen_address = common.get('listen', gs.listen_address)
        gs.listen_port = int(common.get('port', gs.listen_port))
        gs.default_urls = common.get('default_url', '')
        gs.insert_urls = common.get('insert_url', '')
        gs.managed_config_prefix = common.get('managed_config_prefix', '')
        gs.access_token = common.get('api_access_token', '')
        gs.base_path = common.get('base_path', gs.base_path)
        gs.proxy_config = common.get('proxy_config', '')
        gs.proxy_subscription = common.get('proxy_subscription', '')

    node_pref = data.get('node_pref', {})
    if node_pref:
        gs.udp_flag = node_pref.get('udp_flag')
        gs.tfo_flag = node_pref.get('tfo_flag')
        gs.skip_cert_verify = node_pref.get('skip_cert_verify')
        gs.enable_sort = node_pref.get('enable_sort', False)
        gs.filter_deprecated = node_pref.get('filter_deprecated', True)
        gs.clash_use_new_field = node_pref.get('clash_use_new_field_name', False)
        gs.add_emoji = node_pref.get('add_emoji', False)

    server = data.get('server', {})
    if server:
        gs.clash_base = server.get('clash_rule_base', '')
        gs.surge_base = server.get('surge_rule_base', '')
        gs.sing_box_base = server.get('singbox_rule_base', '')

    cache = data.get('cache', {})
    if cache:
        gs.cache_subscription = cache.get('subscription', gs.cache_subscription)
        gs.cache_config = cache.get('config', gs.cache_config)
        gs.cache_ruleset = cache.get('ruleset', gs.cache_ruleset)


def _parse_ini_sections(content: str) -> Dict[str, Dict[str, str]]:
    """Parse an INI-style config into section dict."""
    sections = {}
    current_section = None

    for line in content.split('\n'):
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#'):
            continue

        # Section header
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1].lower()
            if current_section not in sections:
                sections[current_section] = {}
            continue

        # Key-value pair
        if '=' in line and current_section:
            key, _, value = line.partition('=')
            key = trim(key).lower()
            value = trim(value)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            sections[current_section][key] = value

    return sections


def _parse_tribool(val: Any) -> Optional[bool]:
    """Parse a tri-state boolean value."""
    if val is None or val == '':
        return None
    if isinstance(val, bool):
        return val
    return str(val).lower() in ('true', '1', 'yes')


# ==================== External Config Loading ====================

def load_external_config(path: str, ext_config: ExternalConfig) -> int:
    """Load an external configuration file (URL or local path)."""
    proxy = parse_proxy(global_settings.proxy_config)
    content = ""

    if is_link(path):
        content = web_get(path, proxy, global_settings.cache_config)
    elif file_exist(path):
        content = file_get(path)
    else:
        write_log(0, f"External config not found: {path}", LOG_LEVEL_ERROR)
        return -1

    if not content:
        return -1

    try:
        if path.endswith('.toml') or path.endswith('.yml') or path.endswith('.yaml'):
            # YAML/Toml format
            if path.endswith('.toml'):
                try:
                    import toml
                    data = toml.loads(content)
                except ImportError:
                    data = yaml.safe_load(content)
            else:
                data = yaml.safe_load(content)

            if isinstance(data, dict):
                _parse_external_yaml(data, ext_config)
        else:
            # INI format
            _parse_external_ini(content, ext_config)
    except Exception as e:
        write_log(0, f"Error parsing external config: {e}", LOG_LEVEL_ERROR)
        return -1

    return 0


def _parse_external_yaml(data: dict, ext_config: ExternalConfig):
    """Parse external config in YAML/TOML format."""
    # Custom groups
    custom_groups = data.get('custom_proxy_group', data.get('proxy_group', []))
    if isinstance(custom_groups, list):
        for g in custom_groups:
            if isinstance(g, dict):
                ext_config.custom_proxy_group.append(ProxyGroupConfig(
                    Name=g.get('name', ''),
                    Type=ProxyGroupType.Select,
                    Proxies=g.get('proxies', g.get('rule', [])),
                    UsingProvider=g.get('use', []),
                    Url=g.get('url', ''),
                    Interval=int(g.get('interval', 0)),
                ))

    # Rulesets
    rulesets = data.get('surge_ruleset', data.get('ruleset', []))
    if isinstance(rulesets, list):
        for r in rulesets:
            if isinstance(r, dict):
                ext_config.surge_ruleset.append(RulesetConfig(
                    Group=r.get('group', ''),
                    Url=r.get('ruleset', r.get('url', '')),
                    Interval=int(r.get('interval', 86400)),
                ))

    # Base paths
    ext_config.clash_rule_base = data.get('clash_rule_base', '')
    ext_config.surge_rule_base = data.get('surge_rule_base', '')
    ext_config.surfboard_rule_base = data.get('surfboard_rule_base', '')
    ext_config.quan_rule_base = data.get('quan_rule_base', '')
    ext_config.quanx_rule_base = data.get('quanx_rule_base', '')
    ext_config.loon_rule_base = data.get('loon_rule_base', '')
    ext_config.singbox_rule_base = data.get('singbox_rule_base', '')

    # Rename
    renames = data.get('rename', [])
    if isinstance(renames, list):
        for r in renames:
            if isinstance(r, dict):
                ext_config.rename.append(RegexMatchConfig(
                    Match=r.get('match', ''),
                    Replace=r.get('replace', ''),
                    Script=r.get('script', '')
                ))

    # Emoji
    emojis = data.get('emoji', [])
    if isinstance(emojis, list):
        for e in emojis:
            if isinstance(e, dict):
                ext_config.emoji.append(RegexMatchConfig(
                    Match=e.get('match', ''),
                    Replace=e.get('emoji', ''),
                    Script=e.get('script', '')
                ))

    # Include/Exclude
    ext_config.include = data.get('include', data.get('include_remarks', []))
    ext_config.exclude = data.get('exclude', data.get('exclude_remarks', []))

    # Flags
    ext_config.enable_rule_generator = data.get('enable_rule_generator', True)
    ext_config.overwrite_original_rules = data.get('overwrite_original_rules', True)
    ext_config.add_emoji = data.get('add_emoji')
    ext_config.remove_old_emoji = data.get('remove_old_emoji')


def _parse_custom_section(content: str, ext_config: ExternalConfig):
    """Parse [custom] section line by line for ruleset= entries."""
    in_custom = False
    for line in content.split('\n'):
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            in_custom = (line[1:-1].lower() == 'custom')
            continue
        if not in_custom:
            continue

        if '=' in line:
            key, _, value = line.partition('=')
            key = trim(key).lower()
            value = trim(value)

            if key == 'ruleset':
                # Parse comma-separated: group,url_or_inline
                parts = value.split(',', 1)
                if len(parts) >= 2:
                    group = trim(parts[0])
                    url = trim(parts[1])
                    if url.startswith('[]'):
                        # Inline rule: []GEOIP,CN or []FINAL
                        # Store as inline: prefix so refresh_rulesets knows it's inline
                        ext_config.surge_ruleset.append(RulesetConfig(
                            Group=group,
                            Url=f"inline:{url[2:]}",
                            Interval=86400
                        ))
                    else:
                        ext_config.surge_ruleset.append(RulesetConfig(
                            Group=group,
                            Url=url,
                            Interval=86400
                        ))


def _parse_proxy_groups_ini(content: str, ext_config: ExternalConfig):
    """Parse custom_proxy_group= lines from [custom] section.
    Format: custom_proxy_group=<name>`<type>[`<rule>...]
    For url-test/fallback, additional args: `url`interval,timeout,tolerance
    """
    in_custom = False
    for line in content.split('\n'):
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            in_custom = (line[1:-1].lower() == 'custom')
            continue
        if not in_custom:
            continue

        if '=' in line:
            key, _, value = line.partition('=')
            key = trim(key).lower()
            value = trim(value)

            if key == 'custom_proxy_group':
                v_array = value.split('`')
                if len(v_array) < 3:
                    continue

                name = v_array[0]
                gtype_str = v_array[1].lower()

                gtype_map = {
                    'select': ProxyGroupType.Select,
                    'url-test': ProxyGroupType.URLTest,
                    'fallback': ProxyGroupType.Fallback,
                    'load-balance': ProxyGroupType.LoadBalance,
                    'relay': ProxyGroupType.Relay,
                    'ssid': ProxyGroupType.SSID,
                    'smart': ProxyGroupType.Smart,
                }
                gtype = gtype_map.get(gtype_str, ProxyGroupType.Select)

                group = ProxyGroupConfig(Name=name, Type=gtype)

                rules_upper_bound = len(v_array)

                if gtype in (ProxyGroupType.URLTest, ProxyGroupType.LoadBalance,
                             ProxyGroupType.Fallback):
                    if rules_upper_bound >= 5:
                        rules_upper_bound -= 2
                        group.Url = v_array[rules_upper_bound]
                        times = v_array[rules_upper_bound + 1].split(',')
                        if len(times) >= 1:
                            group.Interval = to_int(times[0], 300)
                        if len(times) >= 2:
                            group.Timeout = to_int(times[1], 5)
                        if len(times) >= 3:
                            group.Tolerance = to_int(times[2], 0)

                for i in range(2, rules_upper_bound):
                    rule = v_array[i]
                    if rule.startswith('[]'):
                        rule = rule[2:]  # Remove [] prefix
                    if starts_with(rule, '!!PROVIDER='):
                        group.UsingProvider.append(rule[11:])
                    else:
                        group.Proxies.append(rule)

                ext_config.custom_proxy_group.append(group)


def _parse_external_ini(content: str, ext_config: ExternalConfig):
    """Parse external config in INI format with subconverter's custom binding format."""
    sections = _parse_ini_sections(content)

    # [custom] section - the main configuration
    custom = sections.get('custom', {})

    # Parse ruleset= lines
    # Format: ruleset=<group>,<url_or_inline>
    # Inline rules prefixed with [], e.g. []GEOIP,CN or []FINAL
    ruleset_lines = custom.get('ruleset', '')
    if isinstance(ruleset_lines, str):
        # Multiple ruleset= lines are combined by _parse_ini_sections
        # We need to handle multi-line differently
        pass

    # Actually, _parse_ini_sections only takes the LAST value for duplicate keys.
    # We need to parse line-by-line for multiple ruleset= entries.
    # Let's re-parse the raw [custom] section
    _parse_custom_section(content, ext_config)

    # Parse custom_proxy_group= lines  
    # Format: custom_proxy_group=<name>`<type>`<rule1>`<rule2>...
    _parse_proxy_groups_ini(content, ext_config)

    # [server] section
    server = sections.get('server', {})
    ext_config.clash_rule_base = server.get('clash_rule_base', '')
    ext_config.surge_rule_base = server.get('surge_rule_base', '')

    # [rename] section
    renames = sections.get('rename', {})
    for match, replace in renames.items():
        ext_config.rename.append(RegexMatchConfig(Match=match, Replace=replace))

    # Common flags in [custom]
    ext_config.enable_rule_generator = custom.get('enable_rule_generator', 'true').lower() != 'false'
    ext_config.overwrite_original_rules = custom.get('overwrite_original_rules', 'true').lower() != 'false'


# ==================== Ruleset Refresh ====================

def refresh_rulesets(ruleset_list: List[RulesetConfig],
                     ruleset_content: List[RulesetContent]):
    """Fetch and refresh ruleset contents."""
    proxy = parse_proxy(global_settings.proxy_ruleset)
    ruleset_content.clear()

    for rc in ruleset_list:
        content = ""
        url = rc.Url

        # Determine ruleset type
        rs_type = RULESET_SURGE
        for prefix, rst in RULESET_TYPES.items():
            if starts_with(url, prefix):
                rs_type = rst
                url = url[len(prefix):]
                break

        # Fetch content
        if is_link(url):
            content = web_get(url, proxy, rc.Interval or global_settings.cache_ruleset)
        elif file_exist(url):
            content = file_get(url)
        elif file_exist('base/' + url):
            # Try with base/ prefix (configs are relative to base/)
            content = file_get('base/' + url)
        elif url.startswith('inline:'):
            # Inline rule: the URL is the rule content
            content = url[7:]
        else:
            write_log(0, f"Ruleset file not found: {url}", LOG_LEVEL_WARNING)

        ruleset_content.append(RulesetContent(
            rule_content=content,
            rule_group=rc.Group,
            rule_path=url,
            rule_path_typed=rc.Url,
            rule_type=rs_type,
            update_interval=rc.Interval or 86400
        ))

    write_log(0, f"Refreshed {len(ruleset_content)} rulesets")


RULESET_TYPES = {
    "clash-domain:": RULESET_CLASH_DOMAIN,
    "clash-ipcidr:": RULESET_CLASH_IPCIDR,
    "clash-classic:": RULESET_CLASH_CLASSICAL,
    "quanx:": RULESET_QUANX,
    "surge:": RULESET_SURGE,
}

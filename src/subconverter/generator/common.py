"""Shared generator utilities: node processing, proxy group expansion."""

import re
from typing import List, Optional

from ..config.models import Proxy, ProxyType
from ..config.settings import RegexMatchConfig, ProxyGroupConfig, ProxyGroupType


def apply_rename(remark: str, rename_list: List[RegexMatchConfig]) -> str:
    """Apply rename rules (regex substitutions) to a remark."""
    for rule in rename_list:
        if rule.Script:
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
    """Pre-process nodes: renames, emojis, filters, sorting."""
    for node in nodes:
        node.Remark = apply_rename(node.Remark, settings.rename_list)

    if settings.add_emoji:
        for node in nodes:
            node.Remark = apply_emoji(
                node.Remark, settings.emoji_list,
                settings.add_emoji, settings.remove_emoji
            )

    if settings.append_proxy_type:
        for node in nodes:
            type_str = str(node.Type)
            if not node.Remark.endswith(f"|{type_str}"):
                node.Remark += f"|{type_str}"

    if settings.sort_flag and nodes:
        nodes.sort(key=lambda n: n.Remark)

    if settings.filter_deprecated:
        nodes[:] = [n for n in nodes if n.Type != ProxyType.Unknown]

    for i, node in enumerate(nodes):
        node.Id = i


def expand_group_rules(
    rules: List[str],
    nodes: List[Proxy],
    all_remark_names: List[str],
    all_group_names: set,
) -> List[str]:
    """Expand proxy group rules (. * , regex, group refs) to actual proxy names."""
    result = []
    used = set()
    special_chars = set('.*+?^$()[]{}|\\')

    for rule in rules:
        if rule == '.*':
            for r in all_remark_names:
                if r not in used:
                    result.append(r)
                    used.add(r)
        elif rule.startswith('!!GROUP='):
            target_group = rule[8:]
            for node in nodes:
                if node.Group == target_group and node.Remark not in used:
                    result.append(node.Remark)
                    used.add(node.Remark)
        elif rule in all_group_names:
            if rule not in used:
                result.append(rule)
                used.add(rule)
        elif rule in ('DIRECT', 'REJECT', 'REJECT-TINYGIF'):
            if rule not in used:
                result.append(rule)
                used.add(rule)
        else:
            try:
                pattern = re.compile(rule)
                matched = False
                for node in nodes:
                    if node.Remark and pattern.search(node.Remark):
                        if node.Remark not in used:
                            result.append(node.Remark)
                            used.add(node.Remark)
                            matched = True
                if not matched:
                    if not any(c in rule for c in special_chars):
                        if rule not in used:
                            result.append(rule)
                            used.add(rule)
            except re.error:
                if rule not in used:
                    result.append(rule)
                    used.add(rule)

    return result


class ExtraSettings:
    """Extra settings for node generation."""
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

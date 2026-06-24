"""Rule conversion utilities, ported from generator/config/ruleconvert.cpp."""

import re
from typing import List, Tuple

from ..utils.string_util import (
    starts_with, ends_with, trim, split, join, get_line_break,
    is_ipv4, str_find, reg_replace, replace_all, count_least
)
from ..config.settings import RULESET_SURGE, RULESET_QUANX, RULESET_CLASH_DOMAIN, \
    RULESET_CLASH_IPCIDR, RULESET_CLASH_CLASSICAL

# Rule type definitions
CLASH_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR",
    "GEOIP", "MATCH", "FINAL", "IP-CIDR6", "SRC-PORT", "DST-PORT",
    "PROCESS-NAME", "DOMAIN-REGEX", "GEOSITE", "IP-SUFFIX", "IP-ASN",
    "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX", "IN-PORT", "IN-TYPE",
    "IN-USER", "IN-NAME", "PROCESS-PATH-REGEX", "PROCESS-PATH",
    "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "SUB-RULE",
    "RULE-SET", "AND", "OR", "NOT"
]

SURGE_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR",
    "GEOIP", "MATCH", "FINAL", "IP-CIDR6", "USER-AGENT", "URL-REGEX",
    "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP",
    "DOMAIN-SET"
]

QUANX_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
    "GEOIP", "MATCH", "FINAL", "USER-AGENT", "HOST",
    "HOST-SUFFIX", "HOST-KEYWORD"
]

SURF_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
    "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL", "IP-CIDR6",
    "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"
]

SINGBOX_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
    "MATCH", "FINAL", "IP-VERSION", "INBOUND", "PROTOCOL",
    "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX",
    "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT",
    "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"
]


def convert_ruleset(content: str, ruleset_type: int) -> str:
    """
    Convert ruleset content to Surge-compatible format.

    Args:
        content: Raw ruleset content
        ruleset_type: RULESET_SURGE, RULESET_QUANX, RULESET_CLASH_DOMAIN, etc.

    Returns:
        Converted ruleset content (Surge format)
    """
    if ruleset_type == RULESET_SURGE:
        return content

    if re.search(r'^payload:\r?\n', content):
        # Clash format
        output = re.sub(r'payload:\r?\n', '', content, flags=re.IGNORECASE)
        output = re.sub(r'\s?^?\s*-\s+([\'"]?)(.*)\1$', r'\n\2', output, flags=re.MULTILINE)

        if ruleset_type == RULESET_CLASH_CLASSICAL:
            return output

        lines = output.split('\n')
        result = []
        for line in lines:
            line = trim(line)
            if not line:
                continue
            if str_find(line, '//') != -1:
                line = trim(line[:line.find('//')])

            if line and line[0] not in (';', '#') and not line.startswith('//'):
                pos = line.find('/')
                if pos != -1:
                    if is_ipv4(line[:pos]):
                        result.append(f"IP-CIDR,{line}")
                    else:
                        result.append(f"IP-CIDR6,{line}")
                else:
                    if line[0] == '.' or (len(line) >= 2 and line[:2] == '+.'):
                        # Determine DOMAIN-SUFFIX or DOMAIN-KEYWORD
                        keyword_flag = False
                        while ends_with(line, '.*'):
                            keyword_flag = True
                            line = line[:-2]
                        if keyword_flag:
                            result.append(f"DOMAIN-KEYWORD,{line[2 - (line[0] == '.'):]}")
                        else:
                            result.append(f"DOMAIN-SUFFIX,{line[2 - (line[0] == '.'):]}")
                    else:
                        result.append(f"DOMAIN,{line}")

        return '\n'.join(result)
    else:
        # QuanX format
        output = re.sub(r'^(?i:host)', 'DOMAIN', content, flags=re.MULTILINE)
        output = re.sub(r'^(?i:ip6-cidr)', 'IP-CIDR6', output, flags=re.MULTILINE)
        output = re.sub(
            r'^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\s*?(\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$',
            r'\1\2\3', output, flags=re.MULTILINE
        )
        return output


def transform_rule_to_common(parts: List[str], input_line: str, group: str,
                             no_resolve_only: bool = False) -> str:
    """Transform a single rule line to common format."""
    rule_type = trim(parts[0]).upper()
    content = trim(parts[1]) if len(parts) > 1 else ""
    option = trim(parts[2]) if len(parts) > 2 else ""

    # Handle special types
    if rule_type == "MATCH" or rule_type == "FINAL":
        return f"{rule_type},{group}"

    if rule_type == "RULE-SET" or rule_type == "DOMAIN-SET":
        return f"{rule_type},{content},{group}"

    if no_resolve_only and option != "no-resolve":
        return input_line

    result = f"{rule_type},{content}"

    if option and option != "no-resolve":
        result += f",{option}"
    result += f",{group}"

    return result


def get_ruleset_for_type(content: str, type_int: int, group: str = "",
                         url: str = "") -> str:
    """
    Generate ruleset output for a specific type.
    type_int: 1=Surge, 2=Quantumult X, 3=Clash domain, 4=Clash ipcidr,
              5=Surge DOMAIN-SET, 6=Clash classical
    """
    convert = convert_ruleset(content, RULESET_SURGE)
    lines = convert.strip().split('\n')
    result_lines = []

    for line in lines:
        line = trim(line)
        if not line:
            continue
        if str_find(line, '//') != -1:
            line = trim(line[:line.find('//')])

        if line and line[0] not in (';', '#') and not line.startswith('//'):
            parts = split(line, ',')
            rule_type = trim(parts[0]).upper() if parts else ""

            if type_int == 2:  # QuanX
                if not any(starts_with(line, t) for t in QUANX_RULE_TYPES):
                    continue
            elif type_int == 1:  # Surge
                if not any(starts_with(line, t) for t in SURGE_RULE_TYPES):
                    continue
            elif type_int == 3:  # Clash domain
                if not (starts_with(line, "DOMAIN-SUFFIX,") or starts_with(line, "DOMAIN,")):
                    continue
                content_part = trim(parts[1]) if len(parts) > 1 else ""
                prefix = "'+.'" if rule_type == "DOMAIN-SUFFIX" else "'"
                result_lines.append(f"  - {prefix}{content_part}'")
                continue
            elif type_int == 4:  # Clash ipcidr
                if not (starts_with(line, "IP-CIDR,") or starts_with(line, "IP-CIDR6,")):
                    continue
                content_part = trim(parts[1]) if len(parts) > 1 else ""
                result_lines.append(f"  - '{content_part}'")
                continue
            elif type_int == 5:  # Surge DOMAIN-SET
                if not (starts_with(line, "DOMAIN-SUFFIX,") or starts_with(line, "DOMAIN,")):
                    continue
                content_part = trim(parts[1]) if len(parts) > 1 else ""
                result_lines.append(('.' if rule_type == "DOMAIN-SUFFIX" else '') + content_part)
                continue
            elif type_int == 6:  # Clash classical
                if not any(starts_with(line, t) for t in CLASH_RULE_TYPES):
                    continue
                result_lines.append(f"  - {line}")

        # Replace QuanX specific types
        if type_int == 2:
            if starts_with(line, "IP-CIDR6"):
                line = replace_all(line, "IP-CIDR6", "IP6-CIDR", 1)
            if group:
                line += f",{group}"
        result_lines.append(line)

    return '\n'.join(result_lines) + '\n'

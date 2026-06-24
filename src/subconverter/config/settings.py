"""Global settings and configuration, ported from handler/settings.h and settings.cpp."""

import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum, auto

# Import model types
from ..config.models import ProxyType

# ==================== Enums & Types ====================

class ProxyGroupType(Enum):
    Select = auto()
    URLTest = auto()
    Fallback = auto()
    LoadBalance = auto()
    Relay = auto()
    SSID = auto()
    Smart = auto()

    def __str__(self):
        names = {
            ProxyGroupType.Select: 'select',
            ProxyGroupType.URLTest: 'url-test',
            ProxyGroupType.Fallback: 'fallback',
            ProxyGroupType.LoadBalance: 'load-balance',
            ProxyGroupType.Relay: 'relay',
            ProxyGroupType.SSID: 'ssid',
            ProxyGroupType.Smart: 'smart',
        }
        return names.get(self, self.name.lower())


class BalanceStrategy(Enum):
    ConsistentHashing = auto()
    RoundRobin = auto()

    def __str__(self):
        return self.name.replace('_', '-').lower()


class RulesetType(Enum):
    SurgeRuleset = auto()
    QuantumultX = auto()
    ClashDomain = auto()
    ClashIpCidr = auto()
    ClashClassic = auto()


@dataclass
class RegexMatchConfig:
    Match: str = ""
    Replace: str = ""
    Script: str = ""


@dataclass
class ProxyGroupConfig:
    Name: str = ""
    Type: ProxyGroupType = ProxyGroupType.Select
    Proxies: List[str] = field(default_factory=list)
    UsingProvider: List[str] = field(default_factory=list)
    Url: str = ""
    Interval: int = 0
    Timeout: int = 5
    Tolerance: int = 0
    Strategy: BalanceStrategy = BalanceStrategy.ConsistentHashing
    Lazy: Optional[bool] = None
    DisableUdp: Optional[bool] = None
    Persistent: Optional[bool] = None
    EvaluateBeforeUse: Optional[bool] = None


@dataclass
class RulesetConfig:
    Group: str = ""
    Url: str = ""
    Interval: int = 86400


@dataclass
class RulesetContent:
    rule_content: str = ""
    rule_group: str = ""
    rule_path: str = ""
    rule_path_typed: str = ""
    rule_type: int = 0  # RULESET_SURGE=0, RULESET_QUANX=1, etc.
    update_interval: int = 0


@dataclass
class CronTaskConfig:
    Name: str = ""
    CronExp: str = ""
    Path: str = ""
    Timeout: int = 0


@dataclass
class ExternalConfig:
    custom_proxy_group: List[ProxyGroupConfig] = field(default_factory=list)
    surge_ruleset: List[RulesetConfig] = field(default_factory=list)
    clash_rule_base: str = ""
    surge_rule_base: str = ""
    surfboard_rule_base: str = ""
    mellow_rule_base: str = ""
    quan_rule_base: str = ""
    quanx_rule_base: str = ""
    loon_rule_base: str = ""
    sssub_rule_base: str = ""
    singbox_rule_base: str = ""
    rename: List[RegexMatchConfig] = field(default_factory=list)
    emoji: List[RegexMatchConfig] = field(default_factory=list)
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    overwrite_original_rules: bool = False
    enable_rule_generator: bool = True
    add_emoji: Optional[bool] = None
    remove_old_emoji: Optional[bool] = None


# ==================== RULESET Constants ====================

RULESET_SURGE = 0
RULESET_QUANX = 1
RULESET_CLASH_DOMAIN = 2
RULESET_CLASH_IPCIDR = 3
RULESET_CLASH_CLASSICAL = 4

RULESET_TYPES_MAP = {
    "clash-domain:": RULESET_CLASH_DOMAIN,
    "clash-ipcidr:": RULESET_CLASH_IPCIDR,
    "clash-classic:": RULESET_CLASH_CLASSICAL,
    "quanx:": RULESET_QUANX,
    "surge:": RULESET_SURGE,
}

# ==================== Global Settings ====================

@dataclass
class Settings:
    """Global settings container, ported from Settings struct."""
    
    # Common settings
    pref_path: str = "pref.ini"
    default_ext_config: str = ""
    exclude_remarks: List[str] = field(default_factory=list)
    include_remarks: List[str] = field(default_factory=list)
    custom_rulesets: List[RulesetConfig] = field(default_factory=list)
    stream_node_rules: List[RegexMatchConfig] = field(default_factory=list)
    time_node_rules: List[RegexMatchConfig] = field(default_factory=list)
    rulesets_content: List[RulesetContent] = field(default_factory=list)
    
    listen_address: str = "0.0.0.0"
    default_urls: str = ""
    insert_urls: str = ""
    managed_config_prefix: str = ""
    listen_port: int = 25500
    max_pending_conns: int = 10
    max_concur_threads: int = 4
    
    prepend_insert: bool = True
    skip_failed_links: bool = False
    api_mode: bool = True
    write_managed_config: bool = False
    enable_rule_gen: bool = True
    update_ruleset_on_request: bool = False
    overwrite_original_rules: bool = True
    print_dbg_info: bool = False
    cfw_child_process: bool = False
    append_userinfo: bool = True
    async_fetch_ruleset: bool = False
    surge_resolve_hostname: bool = True
    
    access_token: str = ""
    base_path: str = "base"
    custom_group: str = ""
    log_level: int = 1  # LOG_LEVEL_INFO
    max_allowed_download_size: int = 1048576  # 1MB
    aliases: Dict[str, str] = field(default_factory=dict)
    
    # Template settings
    template_path: str = "templates"
    template_vars: Dict[str, str] = field(default_factory=dict)
    
    # Generator mode
    generator_mode: bool = False
    generate_profiles: str = ""
    
    # Preferences
    reload_conf_on_request: bool = False
    renames: List[RegexMatchConfig] = field(default_factory=list)
    emojis: List[RegexMatchConfig] = field(default_factory=list)
    add_emoji: bool = False
    remove_emoji: bool = False
    append_type: bool = False
    filter_deprecated: bool = True
    udp_flag: Optional[bool] = None
    tfo_flag: Optional[bool] = None
    skip_cert_verify: Optional[bool] = None
    tls13_flag: Optional[bool] = None
    enable_insert: Optional[bool] = False
    enable_sort: bool = False
    update_strict: bool = False
    clash_use_new_field: bool = False
    sing_box_add_clash_modes: bool = True
    clash_proxies_style: str = "flow"
    clash_proxy_groups_style: str = "block"
    
    proxy_config: str = ""
    proxy_ruleset: str = ""
    proxy_subscription: str = ""
    update_interval: int = 0
    
    sort_script: str = ""
    filter_script: str = ""
    
    # Base config paths
    clash_base: str = "base/base/GeneralClashConfig.yml"
    custom_proxy_groups: List[ProxyGroupConfig] = field(default_factory=list)
    surge_base: str = "base/base/surge.conf"
    surfboard_base: str = "base/base/surfboard.conf"
    mellow_base: str = "base/base/mellow.conf"
    quan_base: str = "base/base/quan.conf"
    quan_x_base: str = "base/base/quanx.conf"
    loon_base: str = "base/base/loon.conf"
    ss_sub_base: str = "base/base/shadowsocks_base.json"
    sing_box_base: str = "base/base/singbox.json"
    
    surge_ssr_path: str = ""
    quan_x_dev_id: str = ""
    
    # Cache system
    serve_cache_on_fetch_fail: bool = False
    cache_subscription: int = 60
    cache_config: int = 300
    cache_ruleset: int = 21600
    
    # Limits
    max_allowed_rulesets: int = 64
    max_allowed_rules: int = 32768
    script_clean_context: bool = False
    
    # Cron system
    enable_cron: bool = False
    cron_tasks: List[CronTaskConfig] = field(default_factory=list)


# Global settings instance
global_settings = Settings()

"""HTTP interface handler - ported from handler/interfaces.cpp.

Routes:
- GET /sub           - Main subscription conversion
- GET /version       - Version info
- GET /getruleset    - Convert rulesets
- GET /render        - Template rendering
- GET /sub2clashr    - Simple to ClashR conversion
- GET /surge2clash   - Surge config to Clash conversion
- GET /getprofile    - Load profile and convert
- GET /refreshrules  - Refresh rulesets (needs token)
- GET /readconf      - Reload config (needs token)
- POST /updateconf   - Update config (needs token)
- GET /flushcache    - Flush cache (needs token)
"""

import os
import re
import urllib.parse
from typing import Dict, Optional, List
from copy import deepcopy

from flask import Flask, request, Response, render_template_string

from ..config.models import Proxy, ProxyType
from ..config.settings import (
    global_settings, ExternalConfig, RegexMatchConfig,
    ProxyGroupConfig, RulesetConfig, RulesetContent,
    RULESET_SURGE
)
from ..config.loader import (
    read_conf, load_external_config, refresh_rulesets
)
from ..utils.base64_util import (
    base64_encode, base64_decode,
    url_safe_base64_encode, url_safe_base64_decode
)
from ..utils.url_util import url_encode, url_decode
from ..utils.string_util import (
    split, starts_with, ends_with, trim, replace_all,
    reg_match, reg_find, reg_replace, to_int, count_least,
    is_link, file_exist, file_get, get_line_break, remove_brackets
)
from ..utils.network import web_get, web_post, web_patch, parse_proxy
from ..utils.logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR
from ..parser.subparser import (
    explode, explode_sub, explode_clash_sub, add_nodes,
    explode_vmess_str, explode_ss, explode_ssr, explode_trojan,
    explode_vless, explode_hysteria, explode_hysteria2,
)
from ..generator.subexport import (
    ExtraSettings,
    preprocess_nodes,
    proxy_to_clash,
    proxy_to_surge,
    proxy_to_quanx,
    proxy_to_quan,
    proxy_to_loon,
    proxy_to_single,
    proxy_to_ssd,
    proxy_to_ss_sub,
    proxy_to_mellow,
    proxy_to_singbox,
)
from ..generator.ruleconvert import (
    CLASH_RULE_TYPES, SURGE_RULE_TYPES, QUANX_RULE_TYPES,
    get_ruleset_for_type, convert_ruleset
)

VERSION = "0.1.0"

# User-Agent matching list (same as C++ UAMatchList)
UA_MATCH_LIST = [
    ("ClashForAndroid", r"\/([0-9.]+)", "2.0", "clash", True),
    ("ClashForAndroid", r"\/([0-9.]+)R", "", "clashr", False),
    ("ClashForAndroid", "", "", "clash", False),
    ("ClashforWindows", r"\/([0-9.]+)", "0.11", "clash", True),
    ("ClashforWindows", "", "", "clash", False),
    ("clash-verge", "", "", "clash", True),
    ("ClashX Pro", "", "", "clash", True),
    ("ClashX", r"\/([0-9.]+)", "0.13", "clash", True),
    ("Clash", "", "", "clash", True),
    ("Kitsunebi", "", "", "v2ray", False),
    ("Loon", "", "", "loon", False),
    ("Pharos", "", "", "mixed", False),
    ("Potatso", "", "", "mixed", False),
    ("Quantumult%20X", "", "", "quanx", False),
    ("Quantumult", "", "", "quan", False),
    ("Qv2ray", "", "", "v2ray", False),
    ("Shadowrocket", "", "", "mixed", False),
    ("Surfboard", "", "", "surfboard", False),
    ("Surge", r"\/([0-9.]+).*x86", "906", "surge", False),
    ("Surge", r"\/([0-9.]+).*x86", "368", "surge", False),
    ("Surge", r"\/([0-9.]+)", "1419", "surge", False),
    ("Surge", r"\/([0-9.]+)", "900", "surge", False),
    ("Surge", "", "", "surge", False),
    ("Trojan-Qt5", "", "", "trojan", False),
    ("V2rayU", "", "", "v2ray", False),
    ("V2RayX", "", "", "v2ray", False),
]


# ==================== Helper Functions ====================

def _get_url_arg(args: dict, key: str, default: str = "") -> str:
    """Get URL argument from request args dict."""
    val = args.get(key, default)
    if isinstance(val, list) and val:
        val = val[0]
    return val or default


def _tribool(val) -> Optional[bool]:
    """Parse tri-state bool from string/none."""
    if val is None or val == '':
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        l = val.lower()
        if l in ('true', '1', 'yes'):
            return True
        elif l in ('false', '0', 'no'):
            return False
    return None


def _str_hash(s: str) -> int:
    """Simple string hash."""
    import hashlib
    return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)


def _match_user_agent(user_agent: str) -> tuple:
    """Match user-agent string to determine target format."""
    if not user_agent:
        return None, None, -1

    for head, ver_match, ver_target, target, clash_new_name in UA_MATCH_LIST:
        if user_agent.startswith(head):
            if ver_match:
                m = re.search(ver_match, user_agent)
                if not m:
                    continue
                version = m.group(1) if m.lastindex >= 1 else ""
                if ver_target and version:
                    # Version comparison
                    try:
                        if _ver_less_than(version, ver_target):
                            continue
                    except ValueError:
                        continue
            return target, clash_new_name, -1

    return None, None, -1


def _ver_less_than(a: str, b: str) -> bool:
    """Compare version strings. Returns True if a < b."""
    aparts = [int(x) for x in a.split('.')]
    bparts = [int(x) for x in b.split('.')]
    for av, bv in zip(aparts, bparts):
        if av < bv:
            return True
        if av > bv:
            return False
    return len(aparts) < len(bparts)


def _import_items(items: list, scope_limit: bool = True) -> int:
    """Import items from !!import: directives."""
    result = []
    count = 0
    for item in items:
        if '!!import:' not in item:
            result.append(item)
            continue
        path = item.split(':', 1)[1]
        write_log(0, f"Trying to import items from {path}")

        proxy = parse_proxy(global_settings.proxy_config)
        content = ""
        if file_exist(path):
            content = file_get(path)
        elif is_link(path):
            content = web_get(path, proxy, global_settings.cache_config)

        if not content:
            continue

        for line in content.strip().split('\n'):
            line = trim(line)
            if not line or line[0] in (';', '#') or line.startswith('//'):
                continue
            result.append(line)
            count += 1
    items.clear()
    items.extend(result)
    write_log(0, f"Imported {count} item(s).")
    return 0


# ==================== Route Handlers ====================

def create_app() -> Flask:
    """Create Flask application."""
    app = Flask(__name__)

    @app.route('/version')
    def version():
        return Response(f"subconverter-py v{VERSION} backend\n",
                       mimetype='text/plain')

    @app.route('/')
    def index():
        html_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
        if os.path.isfile(html_path):
            with open(html_path, 'r', encoding='utf-8') as f:
                template = f.read()
            return render_template_string(template, version=VERSION)
        return Response(f"subconverter-py v{VERSION} backend\n", mimetype='text/plain')

    @app.route('/sub', methods=['GET', 'HEAD'])
    def sub():
        return handle_sub(request)

    @app.route('/getruleset')
    def get_ruleset():
        return handle_get_ruleset(request)

    @app.route('/render')
    def render():
        return handle_render(request)

    @app.route('/sub2clashr')
    def sub2clashr():
        return handle_sub2clashr(request)

    @app.route('/surge2clash')
    def surge2clash():
        return handle_surge2clash(request)

    @app.route('/refreshrules')
    def refresh_rules():
        token = request.args.get('token', '')
        if global_settings.access_token and token != global_settings.access_token:
            return Response("Forbidden\n", status=403, mimetype='text/plain')
        refresh_rulesets(global_settings.custom_rulesets, global_settings.rulesets_content)
        return Response("done\n", mimetype='text/plain')

    @app.route('/readconf')
    def read_conf_route():
        token = request.args.get('token', '')
        if global_settings.access_token and token != global_settings.access_token:
            return Response("Forbidden\n", status=403, mimetype='text/plain')
        read_conf()
        if not global_settings.update_ruleset_on_request:
            refresh_rulesets(global_settings.custom_rulesets, global_settings.rulesets_content)
        return Response("done\n", mimetype='text/plain')

    @app.route('/flushcache')
    def flush_cache():
        token = request.args.get('token', '')
        if global_settings.access_token and token != global_settings.access_token:
            return Response("Forbidden\n", status=403, mimetype='text/plain')
        # Remove cache files
        if os.path.exists('cache'):
            for f in os.listdir('cache'):
                os.remove(os.path.join('cache', f))
        return Response("done\n", mimetype='text/plain')

    @app.route('/getprofile')
    def get_profile():
        return handle_get_profile(request)

    return app


def handle_sub(req) -> Response:
    """Main subscription handler - the core /sub endpoint."""
    args = dict(req.args)
    gs = global_settings

    arg_target = _get_url_arg(args, 'target')
    arg_surge_ver = _get_url_arg(args, 'ver')
    arg_clash_new_field = args.get('new_name', None)

    int_surge_ver = to_int(arg_surge_ver, 3)

    # Auto-detect target from User-Agent
    if arg_target == 'auto':
        ua = req.headers.get('User-Agent', '')
        auto_target, auto_clash_new, _ = _match_user_agent(ua)
        if auto_target:
            arg_target = auto_target
            if auto_clash_new is not None and auto_clash_new:
                arg_clash_new_field = 'true'

    # Validate target
    l_simple = False
    valid_targets = {'clash', 'clashr', 'surge', 'surfboard', 'quan', 'quanx',
                     'loon', 'mellow', 'ss', 'ssr', 'ssd', 'sssub', 'v2ray',
                     'trojan', 'mixed', 'singbox', 'vless', 'hysteria2'}
    if arg_target not in valid_targets:
        # Simple target fallback
        if arg_target in ('clash', 'clashr', 'surge', 'quan', 'quanx',
                          'loon', 'surfboard', 'mellow', 'singbox'):
            pass
        elif arg_target in ('ss', 'ssd', 'ssr', 'sssub', 'v2ray',
                            'trojan', 'mixed'):
            l_simple = True
        else:
            return Response("Invalid target!", status=400, mimetype='text/plain')

    # Get parameters
    arg_url = _get_url_arg(args, 'url')
    arg_group_name = _get_url_arg(args, 'group')
    arg_upload_path = _get_url_arg(args, 'upload_path')
    arg_include = _get_url_arg(args, 'include')
    arg_exclude = _get_url_arg(args, 'exclude')
    arg_custom_groups = url_safe_base64_decode(_get_url_arg(args, 'groups'))
    arg_custom_rulesets = url_safe_base64_decode(_get_url_arg(args, 'ruleset'))
    arg_external_config = _get_url_arg(args, 'config')
    arg_device_id = _get_url_arg(args, 'dev_id')
    arg_filename = _get_url_arg(args, 'filename')
    arg_update_interval = _get_url_arg(args, 'interval')
    arg_update_strict = _get_url_arg(args, 'strict')
    arg_renames = _get_url_arg(args, 'rename')
    arg_filter_script = _get_url_arg(args, 'filter_script')

    # Boolean flags
    arg_upload = _tribool(args.get('upload'))
    arg_emoji = _tribool(args.get('emoji'))
    arg_add_emoji = _tribool(args.get('add_emoji'))
    arg_remove_emoji = _tribool(args.get('remove_emoji'))
    arg_append_type = _tribool(args.get('append_type'))
    arg_tfo = _tribool(args.get('tfo'))
    arg_udp = _tribool(args.get('udp'))
    arg_gen_node_list = _tribool(args.get('list'))
    arg_sort = _tribool(args.get('sort'))
    arg_use_sort_script = _tribool(args.get('sort_script'))
    arg_gen_clash_script = _tribool(args.get('script'))
    arg_enable_insert = _tribool(args.get('insert'))
    arg_skip_cert_verify = _tribool(args.get('scv'))
    arg_filter_deprecated = _tribool(args.get('fdn'))
    arg_expand_rulesets = _tribool(args.get('expand'))
    arg_append_userinfo = _tribool(args.get('append_info'))
    arg_prepend_insert = _tribool(args.get('prepend'))
    arg_gen_classical_rule_provider = _tribool(args.get('classic'))
    arg_tls13 = _tribool(args.get('tls13'))

    # Authorization
    authorized = (not gs.api_mode or
                  _get_url_arg(args, 'token') == gs.access_token)

    # Check for blocked regex patterns
    blacklist = {r'(.*)*'}
    if arg_include in blacklist or arg_exclude in blacklist:
        return Response("Invalid request!", status=400, mimetype='text/plain')

    # Base configs
    l_clash_base = gs.clash_base
    l_surge_base = gs.surge_base
    l_surfboard_base = gs.surfboard_base
    l_mellow_base = gs.mellow_base
    l_quan_base = gs.quan_base
    l_quanx_base = gs.quan_x_base
    l_loon_base = gs.loon_base
    l_sssub_base = gs.ss_sub_base
    l_singbox_base = gs.sing_box_base

    # Validate urls
    if not arg_url and (not gs.api_mode or authorized):
        arg_url = gs.default_urls
    if (not arg_url and not (gs.insert_urls and arg_enable_insert)) or not arg_target:
        return Response("Invalid request!", status=400, mimetype='text/plain')

    # Determine interval and strict
    interval = to_int(arg_update_interval, gs.update_interval)
    strict = arg_update_strict.lower() == 'true' if arg_update_strict else gs.update_strict

    # Custom proxy groups
    l_custom_proxy_groups = list(gs.custom_proxy_groups)
    l_custom_rulesets = list(gs.custom_rulesets)
    l_include_remarks = list(gs.include_remarks)
    l_exclude_remarks = list(gs.exclude_remarks)
    l_ruleset_content = list(gs.rulesets_content)

    # Extra settings
    ext = ExtraSettings()
    ext.authorized = authorized
    ext.append_proxy_type = arg_append_type if arg_append_type is not None else gs.append_type

    if arg_target in ('clash', 'clashr') and arg_gen_clash_script is None:
        arg_expand_rulesets = True

    ext.clash_proxies_style = gs.clash_proxies_style
    ext.clash_proxy_groups_style = gs.clash_proxy_groups_style

    # Set flags
    ext.udp = arg_udp if arg_udp is not None else gs.udp_flag
    ext.tfo = arg_tfo if arg_tfo is not None else gs.tfo_flag
    ext.skip_cert_verify = arg_skip_cert_verify if arg_skip_cert_verify is not None else gs.skip_cert_verify
    ext.tls13 = arg_tls13 if arg_tls13 is not None else gs.tls13_flag

    ext.sort_flag = arg_sort if arg_sort is not None else gs.enable_sort
    ext.filter_deprecated = arg_filter_deprecated if arg_filter_deprecated is not None else gs.filter_deprecated
    ext.clash_new_field_name = _tribool(arg_clash_new_field) or gs.clash_use_new_field
    ext.clash_script = arg_gen_clash_script or False
    ext.clash_classical_ruleset = arg_gen_classical_rule_provider or False
    ext.nodelist = arg_gen_node_list or False
    ext.surge_ssr_path = gs.surge_ssr_path
    ext.quanx_dev_id = arg_device_id or gs.quan_x_dev_id
    ext.enable_rule_generator = gs.enable_rule_gen
    ext.overwrite_original_rules = gs.overwrite_original_rules

    if arg_expand_rulesets is False:
        ext.managed_config_prefix = gs.managed_config_prefix

    # Load external config
    ext_config = ExternalConfig()
    if not arg_external_config:
        arg_external_config = gs.default_ext_config
    if arg_external_config:
        write_log(0, "External configuration file provided. Loading...", LOG_LEVEL_INFO)
        if load_external_config(arg_external_config, ext_config) == 0:
            if not ext.nodelist:
                from ..config.loader import check_external_base
                # Check external bases
                if ext_config.clash_rule_base:
                    l_clash_base = ext_config.clash_rule_base or l_clash_base
                if ext_config.surge_rule_base:
                    l_surge_base = ext_config.surge_rule_base or l_surge_base
                if ext_config.surfboard_rule_base:
                    l_surfboard_base = ext_config.surfboard_rule_base or l_surfboard_base
                if ext_config.mellow_rule_base:
                    l_mellow_base = ext_config.mellow_rule_base or l_mellow_base
                if ext_config.quan_rule_base:
                    l_quan_base = ext_config.quan_rule_base or l_quan_base
                if ext_config.quanx_rule_base:
                    l_quanx_base = ext_config.quanx_rule_base or l_quanx_base
                if ext_config.loon_rule_base:
                    l_loon_base = ext_config.loon_rule_base or l_loon_base
                if ext_config.singbox_rule_base:
                    l_singbox_base = ext_config.singbox_rule_base or l_singbox_base
                if ext_config.sssub_rule_base:
                    l_sssub_base = ext_config.sssub_rule_base or l_sssub_base

                if ext_config.surge_ruleset:
                    l_custom_rulesets = ext_config.surge_ruleset
                if ext_config.custom_proxy_group:
                    l_custom_proxy_groups = ext_config.custom_proxy_group
                ext.enable_rule_generator = ext_config.enable_rule_generator
                ext.overwrite_original_rules = ext_config.overwrite_original_rules

            if ext_config.rename:
                ext.rename_list = ext_config.rename
            if ext_config.emoji:
                ext.emoji_list = ext_config.emoji
            if ext_config.include:
                l_include_remarks = ext_config.include
            if ext_config.exclude:
                l_exclude_remarks = ext_config.exclude
    else:
        if not l_simple:
            # Custom groups from URL params
            if arg_custom_groups and not ext.nodelist:
                v_array = arg_custom_groups.split('@')
                # Parse custom groups
                parsed_groups = _parse_custom_groups_ini(v_array)
                l_custom_proxy_groups = parsed_groups if parsed_groups else l_custom_proxy_groups

            # Custom rulesets from URL params
            if arg_custom_rulesets and not ext.nodelist:
                v_array = arg_custom_rulesets.split('@')
                parsed_rulesets = _parse_custom_rulesets_ini(v_array)
                l_custom_rulesets = parsed_rulesets if parsed_rulesets else l_custom_rulesets

    # Refresh rulesets if needed
    if ext.enable_rule_generator and not ext.nodelist and not l_simple:
        if l_custom_rulesets != gs.custom_rulesets:
            l_ruleset_content = []
            refresh_rulesets(l_custom_rulesets, l_ruleset_content)
        else:
            if gs.update_ruleset_on_request:
                l_ruleset_content = []
                refresh_rulesets(gs.custom_rulesets, l_ruleset_content)
            l_ruleset_content = list(gs.rulesets_content)

    # Emoji settings
    if arg_emoji is not None:
        arg_add_emoji = arg_emoji
    ext.add_emoji = arg_add_emoji if arg_add_emoji is not None else gs.add_emoji
    ext.remove_emoji = arg_remove_emoji if arg_remove_emoji is not None else gs.remove_emoji

    # Renames
    if arg_renames:
        ext.rename_list = _parse_rename_ini(arg_renames.split('`'))
    elif not ext.rename_list:
        ext.rename_list = list(gs.renames)

    # Emoji list
    if ext.add_emoji and not ext.emoji_list:
        ext.emoji_list = list(gs.emojis)

    # Include/Exclude filters
    if arg_include and reg_valid(arg_include):
        l_include_remarks = [arg_include]
    if arg_exclude and reg_valid(arg_exclude):
        l_exclude_remarks = [arg_exclude]

    # Proxy settings
    proxy_sub = parse_proxy(gs.proxy_subscription)
    proxy_config = parse_proxy(gs.proxy_config)

    # Parse URLs
    nodes = []
    insert_nodes = []
    group_id = 0

    sub_info = {}

    # Insert URLs first
    if gs.insert_urls and arg_enable_insert:
        group_id = -1
        urls = gs.insert_urls.split('|')
        _import_items(urls, True)
        for url in urls:
            url = trim(url)
            write_log(0, f"Fetching node data from url '{url}'.", LOG_LEVEL_INFO)
            if add_nodes(url, insert_nodes, group_id, proxy_sub,
                        l_exclude_remarks, l_include_remarks) == -1:
                if not gs.skip_failed_links:
                    return Response(
                        f"The following link doesn't contain any valid node info: {url}",
                        status=400, mimetype='text/plain')
            group_id -= 1

    # Main URLs
    urls = arg_url.split('|')
    _import_items(urls, True)
    group_id = 0
    for url in urls:
        url = trim(url)
        write_log(0, f"Fetching node data from url '{url}'.", LOG_LEVEL_INFO)
        if add_nodes(url, nodes, group_id, proxy_sub,
                    l_exclude_remarks, l_include_remarks) == -1:
            if not gs.skip_failed_links:
                return Response(
                    f"The following link doesn't contain any valid node info: {url}",
                    status=400, mimetype='text/plain')
        group_id += 1

    # Check for empty nodes
    if not nodes and not insert_nodes:
        return Response("No nodes were found!", status=400, mimetype='text/plain')

    # Subscription-UserInfo header
    if sub_info.get('info') and arg_append_userinfo if arg_append_userinfo is not None else gs.append_userinfo:
        pass  # Set response header later

    # HEAD request - just return empty
    if req.method == 'HEAD':
        return Response("", mimetype='text/plain')

    # Merge insert nodes
    arg_prepend = arg_prepend_insert if arg_prepend_insert is not None else gs.prepend_insert
    if arg_prepend:
        nodes = insert_nodes + nodes
    else:
        nodes.extend(insert_nodes)

    # Run filter script
    filter_script = gs.filter_script
    if authorized and arg_filter_script:
        filter_script = arg_filter_script
    if filter_script:
        if starts_with(filter_script, "path:"):
            filter_script = file_get(filter_script[5:], False)
        # Basic filter script execution
        try:
            exec_globals = {'nodes': nodes, 'Proxy': Proxy, 'ProxyType': ProxyType}
            exec(filter_script, exec_globals)
            if 'filter' in exec_globals:
                filter_func = exec_globals['filter']
                nodes = [n for n in nodes if filter_func(n)]
        except Exception as e:
            write_log(0, f"Error executing filter script: {e}", LOG_LEVEL_ERROR)

    # Apply group name
    if arg_group_name:
        for node in nodes:
            node.Group = arg_group_name

    # Preprocess nodes
    preprocess_nodes(nodes, ext)

    # Generate output
    output_content = ""
    dummy_ruleset = []

    write_log(0, f"Generate target: {arg_target}", LOG_LEVEL_INFO)

    if arg_target == 'clash' or arg_target == 'clashr':
        clash_r = (arg_target == 'clashr')
        if ext.nodelist:
            import yaml
            yamlnode = {}
            from ..generator.subexport import proxy_to_clash as p2c_yaml
            # For nodelist, we'd need a different YAML-based approach
            output_content = proxy_to_clash(nodes, "", l_ruleset_content,
                                           l_custom_proxy_groups, clash_r, ext)
        else:
            base_content = fetch_file(l_clash_base, proxy_config, gs.cache_config)
            output_content = proxy_to_clash(nodes, base_content, l_ruleset_content,
                                           l_custom_proxy_groups, clash_r, ext)

    elif arg_target == 'surge':
        if ext.nodelist:
            output_content = proxy_to_surge(nodes, "", dummy_ruleset,
                                           l_custom_proxy_groups, int_surge_ver, ext)
        else:
            base_content = fetch_file(l_surge_base, proxy_config, gs.cache_config)
            output_content = proxy_to_surge(nodes, base_content, l_ruleset_content,
                                           l_custom_proxy_groups, int_surge_ver, ext)

    elif arg_target == 'surfboard':
        base_content = fetch_file(l_surfboard_base, proxy_config, gs.cache_config)
        output_content = proxy_to_surge(nodes, base_content, l_ruleset_content,
                                       l_custom_proxy_groups, -3, ext)

    elif arg_target == 'quan':
        base_content = fetch_file(l_quan_base, proxy_config, gs.cache_config)
        output_content = proxy_to_quan(nodes, base_content, l_ruleset_content,
                                       l_custom_proxy_groups, ext)

    elif arg_target == 'quanx':
        base_content = fetch_file(l_quanx_base, proxy_config, gs.cache_config)
        output_content = proxy_to_quanx(nodes, base_content, l_ruleset_content,
                                        l_custom_proxy_groups, ext)

    elif arg_target == 'loon':
        base_content = fetch_file(l_loon_base, proxy_config, gs.cache_config)
        output_content = proxy_to_loon(nodes, base_content, l_ruleset_content,
                                       l_custom_proxy_groups, ext)

    elif arg_target == 'mellow':
        base_content = fetch_file(l_mellow_base, proxy_config, gs.cache_config)
        output_content = proxy_to_mellow(nodes, base_content, l_ruleset_content,
                                        l_custom_proxy_groups, ext)

    elif arg_target == 'sssub':
        base_content = fetch_file(l_sssub_base, proxy_config, gs.cache_config)
        output_content = proxy_to_ss_sub(base_content, nodes, ext)

    elif arg_target == 'ss':
        output_content = proxy_to_single(nodes, 1, ext)

    elif arg_target == 'ssr':
        output_content = proxy_to_single(nodes, 2, ext)

    elif arg_target == 'ssd':
        output_content = proxy_to_ssd(nodes, arg_group_name,
                                      sub_info.get('info', ''), ext)

    elif arg_target == 'v2ray':
        output_content = proxy_to_single(nodes, 4, ext)

    elif arg_target == 'trojan':
        output_content = proxy_to_single(nodes, 8, ext)

    elif arg_target == 'mixed':
        output_content = proxy_to_single(nodes, 63, ext)

    elif arg_target == 'singbox':
        base_content = fetch_file(l_singbox_base, proxy_config, gs.cache_config)
        output_content = proxy_to_singbox(nodes, base_content, l_ruleset_content,
                                         l_custom_proxy_groups, ext)

    # Auto upload to Gist
    if arg_upload:
        upload_gist(arg_target, arg_upload_path, output_content)

    write_log(0, "Generate completed.", LOG_LEVEL_INFO)

    resp = Response(output_content, mimetype='text/plain;charset=utf-8')
    if arg_filename:
        resp.headers['Content-Disposition'] = (
            f"attachment; filename=\"{arg_filename}\"; "
            f"filename*=utf-8''{url_encode(arg_filename)}"
        )
    return resp


def handle_get_ruleset(req) -> Response:
    """Handle /getruleset endpoint."""
    args = dict(req.args)
    url = url_safe_base64_decode(_get_url_arg(args, 'url'))
    type_str = _get_url_arg(args, 'type')
    group = url_safe_base64_decode(_get_url_arg(args, 'group'))

    type_int = to_int(type_str, 0)
    if not url or not type_str or (type_int == 2 and not group) or type_int < 1 or type_int > 6:
        return Response("Invalid request!", status=400, mimetype='text/plain')

    # Fetch ruleset content
    proxy = parse_proxy(global_settings.proxy_ruleset)
    content = web_get(url, proxy, global_settings.cache_ruleset)

    if not content:
        return Response("Invalid request!", status=400, mimetype='text/plain')

    # Convert ruleset
    converted = convert_ruleset(content, RULESET_SURGE)
    output = get_ruleset_for_type(converted, type_int, group, url)

    return Response(output, mimetype='text/plain;charset=utf-8')


def handle_render(req) -> Response:
    """Handle /render endpoint for template rendering."""
    from jinja2 import Template

    args = dict(req.args)
    template_path = _get_url_arg(args, 'template')
    if not template_path:
        return Response("Invalid request!", status=400, mimetype='text/plain')

    content = file_get(template_path) if file_exist(template_path) else ""
    if not content:
        return Response("Template not found!", status=400, mimetype='text/plain')

    try:
        tmpl = Template(content)
        rendered = tmpl.render(**args, global_settings=global_settings)
        return Response(rendered, mimetype='text/plain;charset=utf-8')
    except Exception as e:
        return Response(f"Template render failed: {e}", status=400, mimetype='text/plain')


def handle_sub2clashr(req) -> Response:
    """Handle /sub2clashr endpoint."""
    query = req.query_string.decode() if isinstance(req.query_string, bytes) else req.query_string
    if len(query) <= 8 or not query.startswith("sublink="):
        return Response("Invalid request!", status=400, mimetype='text/plain')

    url = query[8:]
    if url == "sublink":
        return Response("Please insert your subscription link instead of clicking the default link.",
                       status=400, mimetype='text/plain')

    # Set target to clashr and delegate
    from werkzeug.datastructures import ImmutableMultiDict
    new_args = {'target': 'clashr', 'url': url_encode(url)}
    # Create new request args
    req.args = ImmutableMultiDict(new_args)
    return handle_sub(req)


def handle_surge2clash(req) -> Response:
    """Handle /surge2clash endpoint (convert Surge config to Clash)."""
    query = req.query_string.decode() if isinstance(req.query_string, bytes) else req.query_string
    if len(query) <= 5 or not query.startswith("link="):
        return Response("Invalid request!", status=400, mimetype='text/plain')

    url = query[5:]
    if url == "link":
        return Response("Please insert your subscription link instead of clicking the default link.",
                       status=400, mimetype='text/plain')

    write_log(0, f"SurgeConfToClash called with url '{url}'.", LOG_LEVEL_INFO)

    # Fetch Surge config
    proxy = parse_proxy(global_settings.proxy_config)
    content = web_get(url, proxy, global_settings.cache_config)

    if not content:
        return Response("Failed to fetch Surge config.", status=400, mimetype='text/plain')

    # Parse Surge config and convert to Clash
    return _surge_to_clash(content, url)


def _surge_to_clash(content: str, url: str) -> Response:
    """Convert a Surge configuration to Clash format."""
    import yaml as yaml_lib

    sections = {}
    current_section = None

    for line in content.split('\n'):
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)

    if 'Proxy' not in sections or 'Proxy Group' not in sections or 'Rule' not in sections:
        return Response("Incomplete surge config! Missing critical sections!",
                       status=400, mimetype='text/plain')

    # Build Clash config
    config = {}
    config['proxies'] = []
    config['proxy-groups'] = []
    config['rules'] = []

    # Parse proxies
    for line in sections.get('Proxy', []):
        if '=' in line:
            name, _, spec = line.partition('=')
            name = trim(name)
            spec = trim(spec)
            # Simplified parsing - just add as custom proxy
            parts = spec.split(',')
            if len(parts) >= 3:
                ptype = trim(parts[0])
                server = trim(parts[1])
                port = trim(parts[2])
                proxy = {'name': name, 'server': server, 'port': to_int(port)}
                if ptype == 'ss':
                    proxy['type'] = 'ss'
                    for p in parts[3:]:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            if 'encrypt' in k.lower():
                                proxy['cipher'] = trim(v)
                            elif 'password' in k.lower():
                                proxy['password'] = trim(v)
                elif ptype == 'vmess':
                    proxy['type'] = 'vmess'
                    proxy['uuid'] = name
                config['proxies'].append(proxy)

    # Parse proxy groups
    for line in sections.get('Proxy Group', []):
        if '=' in line:
            name, _, spec = line.partition('=')
            name = trim(name)
            parts = [trim(p) for p in spec.split(',')]
            if len(parts) >= 2:
                gtype = parts[0]
                group = {'name': name, 'type': gtype, 'proxies': parts[1:]}
                config['proxy-groups'].append(group)

    # Parse rules
    for line in sections.get('Rule', []):
        parts = [trim(p) for p in line.split(',')]
        if len(parts) >= 2:
            config['rules'].append(','.join(parts))

    return Response(yaml_lib.dump(config, allow_unicode=True, default_flow_style=False),
                   mimetype='text/plain;charset=utf-8')


def handle_get_profile(req) -> Response:
    """Handle /getprofile endpoint."""
    args = dict(req.args)
    name = _get_url_arg(args, 'name')
    token = _get_url_arg(args, 'token')

    profiles = name.split('|')
    if token != global_settings.access_token or not profiles:
        return Response("Forbidden", status=403, mimetype='text/plain')

    profile_name = profiles[0]
    if not file_exist(profile_name):
        return Response("Profile not found", status=404, mimetype='text/plain')

    write_log(0, f"Trying to load profile '{profile_name}'.", LOG_LEVEL_INFO)

    profile_content = file_get(profile_name)
    sections = _parse_ini_sections(profile_content)

    prof = sections.get('profile', {})
    if not prof:
        return Response("Broken profile!", status=500, mimetype='text/plain')

    # Extract URL from profile
    profile_url = prof.get('url', '')
    if not profile_url:
        return Response("Profile does not have url key!", status=500, mimetype='text/plain')

    # Build new request
    from werkzeug.datastructures import ImmutableMultiDict
    new_args = dict(args)
    new_args['url'] = profile_url
    request.args = ImmutableMultiDict(new_args)

    return handle_sub(request)


# ==================== Helper Functions ====================

def fetch_file(path: str, proxy: str, cache_ttl: int = 0) -> str:
    """Fetch a file from URL or local path."""
    if not path:
        return ""
    if is_link(path):
        return web_get(path, proxy, cache_ttl)
    elif file_exist(path):
        return file_get(path)
    return ""


def _parse_ini_sections(content: str) -> Dict[str, Dict[str, str]]:
    """Parse INI-style content into a dict of sections."""
    sections = {}
    current_section = None

    for line in content.split('\n'):
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1].lower()
            if current_section not in sections:
                sections[current_section] = {}
            continue
        if '=' in line and current_section:
            key, _, value = line.partition('=')
            key = trim(key).lower()
            value = trim(value)
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            sections[current_section][key] = value

    return sections


def _parse_custom_groups_ini(arr: List[str]) -> List[ProxyGroupConfig]:
    """Parse custom proxy groups from INI format strings."""
    result = []
    for item in arr:
        v_array = item.split('`')
        if len(v_array) < 3:
            continue

        name = v_array[0]
        gtype_str = v_array[1]

        gtype_map = {
            'select': ProxyGroupType.Select,
            'url-test': ProxyGroupType.URLTest,
            'fallback': ProxyGroupType.Fallback,
            'load-balance': ProxyGroupType.LoadBalance,
            'relay': ProxyGroupType.Relay,
            'ssid': ProxyGroupType.SSID,
            'smart': ProxyGroupType.Smart,
        }
        gtype = gtype_map.get(gtype_str.lower())
        if gtype is None:
            continue

        group = ProxyGroupConfig(Name=name, Type=gtype)

        upper_bound = len(v_array)
        if gtype in (ProxyGroupType.URLTest, ProxyGroupType.LoadBalance,
                     ProxyGroupType.Fallback) and upper_bound >= 5:
            upper_bound -= 2
            group.Url = v_array[upper_bound]
            times = split(v_array[upper_bound + 1], ',')
            if len(times) >= 1:
                group.Interval = to_int(times[0])
            if len(times) >= 2:
                group.Timeout = to_int(times[1])
            if len(times) >= 3:
                group.Tolerance = to_int(times[2])

        for i in range(2, upper_bound):
            if starts_with(v_array[i], "!!PROVIDER="):
                group.UsingProvider.append(v_array[i][11:])
            else:
                group.Proxies.append(v_array[i])

        result.append(group)
    return result


def _parse_custom_rulesets_ini(arr: List[str]) -> List[RulesetConfig]:
    """Parse custom rulesets from INI format strings."""
    result = []
    for item in arr:
        pos = item.find(',')
        if pos == -1:
            continue
        group_name = item[:pos]
        url = item[pos + 1:]
        rc = RulesetConfig(Group=group_name, Url=url)

        epos = url.rfind(',')
        if epos != -1 and epos != pos:
            rc.Interval = to_int(url[epos + 1:])
            rc.Url = url[:epos]

        result.append(rc)
    return result


def _parse_rename_ini(arr: List[str]) -> List[RegexMatchConfig]:
    """Parse rename configurations from INI format strings."""
    result = []
    for item in arr:
        if starts_with(item, "script:"):
            result.append(RegexMatchConfig(Script=item[7:]))
            continue
        parts = item.rsplit('@', 1) if '@' in item else item.rsplit('`', 1)
        if len(parts) == 2:
            result.append(RegexMatchConfig(Match=parts[0], Replace=parts[1]))
        elif len(parts) == 1:
            result.append(RegexMatchConfig(Match=parts[0], Replace=""))
    return result


def upload_gist(name: str, path: str, content: str) -> int:
    """Upload content to GitHub Gist."""
    gist_conf = "gistconf.ini"
    if not file_exist(gist_conf):
        write_log(0, "gistconf.ini not found. Skipping...", LOG_LEVEL_ERROR)
        return -1

    sections = _parse_ini_sections(file_get(gist_conf))
    common = sections.get('common', {})
    token = common.get('token', '')
    gist_id = common.get('id', '')
    username = common.get('username', '')

    if not token:
        write_log(0, "No token is provided. Skipping...", LOG_LEVEL_ERROR)
        return -1

    if not path:
        # Use path from gistconf
        path_section = sections.get(path.lower(), {})
        path = path_section.get('path', name)

    import json as json_lib
    data = {
        "description": "subconverter",
        "public": False,
        "files": {
            path: {
                "content": content
            }
        }
    }

    proxy = parse_proxy(global_settings.proxy_config)

    if not gist_id:
        write_log(0, "No Gist id is provided. Creating new Gist...", LOG_LEVEL_INFO)
        status_code, resp_data = web_post(
            "https://api.github.com/gists",
            json_lib.dumps(data), proxy,
            {"Authorization": f"token {token}"}
        )
        if status_code != 201:
            write_log(0, f"Create new Gist failed! Return code: {status_code}", LOG_LEVEL_ERROR)
            return -1
    else:
        write_log(0, "Gist id provided. Modifying Gist...", LOG_LEVEL_INFO)
        status_code, resp_data = web_patch(
            f"https://api.github.com/gists/{gist_id}",
            json_lib.dumps(data), proxy,
            {"Authorization": f"token {token}"}
        )
        if status_code != 200:
            write_log(0, f"Modify Gist failed! Return code: {status_code}", LOG_LEVEL_ERROR)
            return -1

    # Update gistconf.ini with new id/username
    try:
        result = json_lib.loads(resp_data)
        new_id = result.get('id', '')
        new_username = result.get('owner', {}).get('login', '')
        raw_url = f"https://gist.githubusercontent.com/{new_username}/{new_id}/raw/{path}"

        write_log(0, f"Writing to Gist success!\nGenerator: {name}\nPath: {path}\nRaw URL: {raw_url}", LOG_LEVEL_INFO)

        # Update gistconf.ini
        new_content = f"[common]\ntoken = {token}\nid = {new_id}\nusername = {new_username}\n"
        new_content += f"\n[{path}]\ntype = {name}\nurl = {raw_url}\n"
        file_write(gist_conf, new_content)
    except Exception as e:
        write_log(0, f"Failed to update gistconf: {e}", LOG_LEVEL_WARNING)

    return 0

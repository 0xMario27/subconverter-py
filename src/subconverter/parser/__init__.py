"""Proxy link parsers - public API."""

from .dispatcher import explode
from .proxy_types import (
    explode_ss, explode_ssr, explode_vmess, explode_trojan, explode_vless,
    explode_hysteria, explode_hysteria2, explode_tuic,
    explode_socks, explode_http_link, explode_snell, explode_wireguard,
    explode_anytls, explode_mieru, explode_tg,
)
from .subscription import explode_sub, explode_clash_sub, add_nodes
from .constructors import (
    ss_construct, ssr_construct, vmess_construct, vless_construct,
    trojan_construct, socks_construct, http_construct,
    hysteria_construct, hysteria2_construct, tuic_construct,
)

SS_CIPHERS = [
    "rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "bf-cfb", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "salsa20", "chacha20", "chacha20-ietf",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305",
    "2022-blake3-chacha8-poly1305"
]

SSR_CIPHERS = SS_CIPHERS + [
    "none", "table", "rc4", "cast5-cfb", "des-cfb",
    "idea-cfb", "rc2-cfb", "seed-cfb"
]

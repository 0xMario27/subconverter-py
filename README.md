# subconverter-py

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**subconverter-py** is a Python port of the original [subconverter](https://github.com/tindy2013/subconverter) — a utility to convert between various proxy subscription formats.

## Supported Formats

| Type | As Source | As Target |
|------|:---------:|:---------:|
| Clash / ClashR | ✓ | ✓ |
| Surge 2/3/4/5 | ✓ | ✓ |
| Quantumult / Quantumult X | ✓ | ✓ |
| Loon | ✓ | ✓ |
| Surfboard | ✓ | ✓ |
| SS / SSR / SSD | ✓ | ✓ |
| V2Ray / VMess | ✓ | ✓ |
| Trojan | ✓ | ✓ |
| VLESS | ✓ | ✓ |
| Hysteria / Hysteria2 | ✓ | ✓ |
| TUIC | ✓ | ✓ |
| Sing-box | ✓ | ✓ |
| SOCKS5 / HTTP(S) | ✓ | ✓ |

## Quick Start

### Using Docker

```bash
docker run -d --restart=always -p 25500:25500 ghcr.io/0xmario27/subconverter-py:latest
curl http://localhost:25500/version
```

### Using uv (local development)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run
uv run subconverter
```

## Usage

```txt
http://127.0.0.1:25500/sub?target=%TARGET%&url=%URL%&config=%CONFIG%
```

### Example

Convert a subscription to Clash format:

```
http://127.0.0.1:25500/sub?target=clash&url=https%3A%2F%2Fyour-subscription-url.com
```

Merge two subscriptions:

```
Subscribe URL 1: https://sub1.com/xxx
Subscribe URL 2: https://sub2.com/yyy
Merge: https://sub1.com/xxx|https://sub2.com/yyy
URL Encode: https%3A%2F%2Fsub1.com%2Fxxx%7Chttps%3A%2F%2Fsub2.com%2Fyyy
Final: http://127.0.0.1:25500/sub?target=clash&url=<encoded>
```

## Configuration

Configuration file is `pref.ini`, `pref.toml`, or `pref.yml` in the running directory.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Listen port (default: 25500) |
| `API_MODE` | Enable API mode (default: true) |
| `API_TOKEN` | API access token |
| `MANAGED_PREFIX` | Managed config URL prefix |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sub` | GET/HEAD | Main subscription conversion |
| `/version` | GET | Version info |
| `/getruleset` | GET | Convert rulesets |
| `/render` | GET | Template rendering |
| `/sub2clashr` | GET | Simple to ClashR |
| `/surge2clash` | GET | Surge config to Clash |
| `/refreshrules` | GET | Refresh rulesets (needs token) |
| `/readconf` | GET | Reload config (needs token) |
| `/flushcache` | GET | Flush cache (needs token) |

## Differences from C++ version

1. **Written in Python** — easier to modify and extend
2. **Flask-based HTTP server** — simpler deployment
3. **No QuickJS dependency** — filter scripts use Python's `exec()`
4. **Simplified template engine** — uses Jinja2
5. **uv package manager** — fast dependency resolution

## License

MIT

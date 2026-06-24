# subconverter-py

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://docker.com)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

**subconverter-py** — Utility to convert between various proxy subscription formats. Pure Python rewrite with zero external runtime dependencies.

> Original project: [tindy2013/subconverter](https://github.com/tindy2013/subconverter)
>
> 中文文档: [README-cn.md](README-cn.md)

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/0xMario27/subconverter-py.git
cd subconverter-py

make build    # Build image
make run      # Start (port 25500)

# Custom port
PORT=58080 make run
```

```bash
make stop     # Stop container
make restart  # Restart
make logs     # View logs
make clean    # Remove container + image
```

Open `http://localhost:25500` in your browser for the Web UI.

### Local Development

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

cd subconverter-py
uv sync
uv run subconverter --port 25500
```

---

## 📰 Web UI

Built-in vintage newspaper-themed web interface. No frontend frameworks required:

- 🎨 **1920s Newspaper Aesthetic** — parchment paper, Times New Roman masthead, multi-column layout
- ✨ **Magic Particles** — floating golden ink dust animation
- 📋 **Editorial Desk** — paste subscription link → pick target format → pick rule template → convert
- 📥 **Download / Copy** — save or copy the result as a config file
- 📡 **API Reference** — all endpoints listed at page bottom

---

## 🔌 API

### Core Endpoint

```
GET /sub?target=<type>&url=<encoded_url>&config=<template>
```

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `target` | ✅ | Target format (see supported list below) |
| `url` | ✅ | Subscription URL(s), `\|`-separated. Must be URL-encoded |
| `config` | ❌ | External config template path (optional), URL-encoded |
| `ver` | ❌ | Surge version number (default: 3) |
| `emoji` | ❌ | Enable emoji injection |
| `udp` / `tfo` / `scv` | ❌ | Override node parameters |
| `filename` | ❌ | Download filename for Content-Disposition |

### Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/version` | GET | Version info |
| `/getruleset` | GET | Ruleset format conversion |
| `/render` | GET | Template rendering |
| `/refreshrules` | GET | Refresh ruleset cache (requires token) |
| `/readconf` | GET | Reload configuration (requires token) |
| `/updateconf` | POST | Update configuration (requires token) |
| `/flushcache` | GET | Clear all caches |
| `/api/configs` | GET | List available rule templates |

---

## 📋 Supported Formats

| Format | Input | Output |
|--------|:-----:|:------:|
| **Clash / Clash Meta** | ✅ | ✅ |
| **ClashR** | ✅ | ✅ |
| **Surge 2–6** | ✅ | ✅ |
| **Quantumult** | ✅ | ✅ |
| **Quantumult X** | ✅ | ✅ |
| **Loon** | ✅ | ✅ |
| **Surfboard** | ✅ | ✅ |
| **sing-box** | ✅ | ✅ |
| **Shadowsocks (SIP002)** | ✅ | ✅ |
| **ShadowsocksR** | ✅ | ✅ |
| **SS Android** | ✅ | ✅ |
| **SSD** | ✅ | ✅ |
| **VMess / V2Ray** | ✅ | ✅ |
| **Trojan** | ✅ | ✅ |
| **VLESS** | ✅ | ✅ |
| **Hysteria / Hysteria2** | ✅ | ✅ |
| **TUIC** | ✅ | ✅ |
| **AnyTLS** | ✅ | ✅ |
| **Mieru** | ✅ | ✅ |
| **WireGuard** | ✅ | ✅ |
| **SOCKS5 / HTTP(S)** | ✅ | ✅ |
| **Snell** | ✅ | ✅ |
| **Telegram-style links** | ✅ | ❌ |

---

## 📂 Rule Templates

**32 ACL4SSR rule templates** included out of the box:

| Template | Use Case |
|----------|----------|
| `ACL4SSR` | Basic: ad-blocking, Microsoft/Apple routing, auto speed-test |
| `ACL4SSR_Mini` | Minimal: core rules only |
| `ACL4SSR_Online` | Online: remote ruleset loading |
| `ACL4SSR_Online_Full` | Full: all routing + region groups + Netflix/YouTube |
| `ACL4SSR_Online_Full_MultiMode` | Multi-mode: compatible with multiple clients |
| `ACL4SSR_WithChinaIp` | Enhanced China IP ranges |
| `ACL4SSR_NoApple` / `NoMicrosoft` | Exclude Apple/Microsoft routing |
| ... | 32 templates total |

Drop custom `.ini` files into `base/config/` to auto-detect them.

---

## ⚙️ Configuration

Configuration file is `pref.ini`, `pref.toml`, or `pref.yml` in the working directory. On first startup, it auto-copies from `pref.example.*`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Listen port | `25500` |
| `API_MODE` | API authentication mode | `true` |
| `API_TOKEN` | Management endpoint token | (empty) |
| `MANAGED_PREFIX` | Managed config URL prefix | (empty) |

---

## 🐳 Docker

```bash
# Build
docker build -t subconverter-py .

# Run
docker run -d --restart=always \
  --name subconverter-py \
  -p 25500:25500 \
  -v $(pwd)/cache:/app/base/cache \
  subconverter-py

# Or use Makefile
make build && make run
```

Mount the `cache` directory to persist and reuse downloaded rulesets.

---

## 🏗️ Project Structure

```
subconverter-py/
├── Makefile               # Docker build/run commands
├── Dockerfile             # Multi-stage build
├── pyproject.toml         # uv package manager
├── src/subconverter/
│   ├── main.py            # Entry point (CLI + WSGI)
│   ├── config/            # Data models + global settings + config loader
│   ├── parser/            # Proxy link parsers (14 protocols)
│   │   ├── common.py      # Shared construct helpers
│   │   ├── constructors.py
│   │   ├── proxy_types.py # SS / SSR / VMess / Trojan / VLESS / ...
│   │   ├── dispatcher.py  # Prefix-based routing
│   │   └── subscription.py # Subscription + Clash YAML parsing
│   ├── generator/         # Output generators
│   │   ├── common.py      # ExtraSettings + proxy group expander
│   │   ├── clash.py       # Clash / Clash Meta (flow style + rule-providers)
│   │   ├── surge.py       # Surge / Loon / Quantumult / Surfboard
│   │   ├── quanx.py       # Quantumult X
│   │   ├── singbox.py     # sing-box
│   │   ├── simple.py      # SS / SSR / V2Ray / Trojan plain subscriptions
│   │   └── ruleconvert.py # Ruleset format conversion
│   ├── handler/           # HTTP interface (Flask)
│   │   ├── interfaces.py  # Routes + handler logic
│   │   └── templates/     # Web UI template
│   └── utils/             # Utilities (Base64 / URL / network / logging)
├── base/                  # Base templates + rulesets + configs
│   ├── base/              # Per-client base config templates
│   ├── config/            # 32 ACL4SSR rule templates
│   ├── rules/             # Local rule files
│   └── snippets/          # Emoji / rename / group snippets
└── cache/                 # Runtime cache directory
```

---

## 🔄 Differences from C++ Original

| Aspect | C++ Original | Python Port |
|--------|-------------|-------------|
| Language | C++20 + CMake | Python 3.10+ |
| HTTP Server | cpp-httplib | Flask + Waitress |
| Script engine | QuickJS | Python exec() |
| Templates | inja | Jinja2 |
| Package mgmt | CMake + git submodules | uv |
| Docker | Alpine + manual dep build | `uv pip install` one-liner |
| Web UI | None | Built-in vintage newspaper UI |
| New protocols | — | AnyTLS / Mieru |

---

## 📄 License & Attribution

This project is licensed under **GNU General Public License v3.0** (GPLv3).
See [LICENSE](LICENSE) for full terms.

### Third-party Components

| Component | Source | License |
|-----------|--------|---------|
| Original subconverter | [tindy2013/subconverter](https://github.com/tindy2013/subconverter) | GPLv3 |
| ACL4SSR rulesets | [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | CC-BY-SA-4.0 |
| DivineEngine rulesets | [DivineEngine/Profiles](https://github.com/DivineEngine/Profiles) | — |
| lhie1 rules | [lhie1/Rules](https://github.com/lhie1/Rules) | — |
| NobyDa rules | [NobyDa/Scripts](https://github.com/NobyDa/Scripts) | — |

Detailed attributions in [NOTICE](NOTICE).

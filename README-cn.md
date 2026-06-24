# subconverter-py

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://docker.com)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

**subconverter-py** — 在各种代理订阅格式之间进行转换的实用工具。纯 Python 重写，零外部运行时依赖。

> 原项目：[tindy2013/subconverter](https://github.com/tindy2013/subconverter)
>
> English docs: [README.md](README.md)

---

## 🚀 快速开始

### Docker（推荐）

```bash
git clone https://github.com/0xMario27/subconverter-py.git
cd subconverter-py

make build    # 构建镜像
make run      # 启动（默认端口 25500）

# 指定端口
PORT=58080 make run
```

```bash
make stop     # 停止容器
make restart  # 重启
make logs     # 查看日志
make clean    # 删除容器和镜像
```

浏览器打开 `http://localhost:25500` 即可使用网页界面。

### 本地开发

```bash
# 安装 uv
curl -LsSf https://astral.sh/uv/install.sh | sh

cd subconverter-py
uv sync
uv run subconverter --port 25500
```

---

## 📰 网页界面

内置复古报纸风格网页界面，无需任何前端框架：

- 🎨 **1920s 报纸美学** — 泛黄纸张底色、Times New Roman 报头、多栏排版
- ✨ **魔法粒子动画** — 金色墨水尘埃漂浮效果
- 📋 **编辑室表单** — 输入订阅链接 → 选目标格式 → 选规则模板 → 一键转换
- 📥 **下载 / 复制** — 结果可直接复制或下载为配置文件
- 📡 **API 端点展示** — 页面底部列出所有可用接口

---

## 🔌 API 接口

### 核心转换接口

```
GET /sub?target=<type>&url=<encoded_url>&config=<template>
```

| 参数 | 必填 | 说明 |
|------|:----:|------|
| `target` | ✅ | 目标格式，参见下方支持列表 |
| `url` | ✅ | 订阅链接（多个用 `\|` 分隔），需 URL 编码 |
| `config` | ❌ | 外部规则模板路径（可选），需 URL 编码 |
| `ver` | ❌ | Surge 版本号（默认 3） |
| `emoji` | ❌ | 是否注入 Emoji 标识 |
| `udp` / `tfo` / `scv` | ❌ | 覆盖节点参数 |
| `filename` | ❌ | 下载文件名（Content-Disposition） |

### 管理接口

| 端点 | 方法 | 说明 |
|------|------|------|
| `/version` | GET | 版本信息 |
| `/getruleset` | GET | 规则集格式转换 |
| `/render` | GET | 模板渲染 |
| `/refreshrules` | GET | 刷新规则集缓存（需 Token） |
| `/readconf` | GET | 重载配置文件（需 Token） |
| `/updateconf` | POST | 更新配置文件（需 Token） |
| `/flushcache` | GET | 清空所有缓存 |
| `/api/configs` | GET | 列出可用规则模板 |

---

## 📋 支持格式

| 格式 | 作为输入 | 作为输出 |
|------|:--:|:--:|
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
| **Telegram 风格链接** | ✅ | ❌ |

---

## 📂 规则模板

内置 **32 个 ACL4SSR 规则模板**，开箱即用：

| 模板 | 适用场景 |
|------|----------|
| `ACL4SSR` | 基础版：去广告、微软/苹果分流、自动测速 |
| `ACL4SSR_Mini` | 精简版：仅核心规则 |
| `ACL4SSR_Online` | 在线版：规则集远程加载 |
| `ACL4SSR_Online_Full` | 完整版：全部分流 + 地区分组 + Netflix/YouTube |
| `ACL4SSR_Online_Full_MultiMode` | 多模式版：兼容多种客户端 |
| `ACL4SSR_WithChinaIp` | 含中国 IP 段增强 |
| `ACL4SSR_NoApple` / `NoMicrosoft` | 不含苹果/微软分流 |
| ... | 共 32 种 |

将自定义 `.ini` 文件放入 `base/config/` 目录即可自动识别。

---

## ⚙️ 配置说明

配置文件为 `pref.ini`、`pref.toml` 或 `pref.yml`，放在运行目录下。首次启动会自动从 `pref.example.*` 复制一份。

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PORT` | 监听端口 | `25500` |
| `API_MODE` | API 认证模式 | `true` |
| `API_TOKEN` | 管理接口访问令牌 | （空） |
| `MANAGED_PREFIX` | 托管配置 URL 前缀 | （空） |

---

## 🐳 Docker

```bash
# 构建镜像
docker build -t subconverter-py .

# 运行容器
docker run -d --restart=always \
  --name subconverter-py \
  -p 25500:25500 \
  -v $(pwd)/cache:/app/base/cache \
  subconverter-py

# 或使用 Makefile
make build && make run
```

挂载 `cache` 目录可持久化并复用已下载的规则集。

---

## 🏗️ 项目结构

```
subconverter-py/
├── Makefile               # Docker 构建/运行命令
├── Dockerfile             # 多阶段构建
├── pyproject.toml         # uv 包管理配置
├── src/subconverter/
│   ├── main.py            # 入口（CLI + WSGI 启动）
│   ├── config/            # 数据模型 + 全局设置 + 配置加载
│   ├── parser/            # 代理链接解析（14 种协议）
│   │   ├── common.py      # 公共构造工具
│   │   ├── constructors.py  # 节点构造器
│   │   ├── proxy_types.py # SS / SSR / VMess / Trojan / VLESS / ...
│   │   ├── dispatcher.py  # 前缀映射分发器
│   │   └── subscription.py # 订阅解析 + Clash YAML 解析
│   ├── generator/         # 输出生成器
│   │   ├── common.py      # ExtraSettings + 代理组展开逻辑
│   │   ├── clash.py       # Clash / Clash Meta（flow style + rule-provider）
│   │   ├── surge.py       # Surge / Loon / Quantumult / Surfboard
│   │   ├── quanx.py       # Quantumult X
│   │   ├── singbox.py     # sing-box
│   │   ├── simple.py      # SS / SSR / V2Ray / Trojan 简单订阅
│   │   └── ruleconvert.py # 规则格式转换
│   ├── handler/           # HTTP 接口（Flask）
│   │   ├── interfaces.py  # 路由 + 处理逻辑
│   │   └── templates/     # 网页模板
│   └── utils/             # 工具库（Base64 / URL / 网络 / 日志）
├── base/                  # 基础模板 + 规则集 + 配置文件
│   ├── base/              # 各客户端基础配置模板
│   ├── config/            # 32 个 ACL4SSR 规则模板
│   ├── rules/             # 本地规则文件
│   └── snippets/          # Emoji / 重命名 / 分组片段
└── cache/                 # 运行时缓存目录
```

---

## 🔄 与 C++ 原版的差异

| 对比维度 | C++ 原版 | Python 版 |
|----------|----------|-----------|
| 编程语言 | C++20 + CMake | Python 3.10+ |
| HTTP 服务器 | cpp-httplib | Flask + Waitress |
| 脚本引擎 | QuickJS | Python exec() |
| 模板引擎 | inja | Jinja2 |
| 包管理 | CMake + git submodules | uv |
| Docker 构建 | Alpine + 手动编译依赖 | `uv pip install` 一行搞定 |
| Web 界面 | 无 | 内置复古报纸风格界面 |
| 新增协议 | — | AnyTLS / Mieru |

---

## 📄 许可证

MIT

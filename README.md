# VulnWatchdog

VulnWatchdog 是一个自动化的 CVE 漏洞监控和分析工具，通过监控 GitHub 上的 CVE 相关仓库，获取漏洞信息和 POC 代码，并使用 GPT 进行智能分析，生成结构化的分析报告。

## ✨ 主要特性

- 🔍 **自动监控** - 每小时监控 GitHub CVE 相关仓库更新
- 📊 **漏洞解析** - 自动获取并解析 CVE 漏洞详细信息
- 🤖 **智能分析** - 使用 GPT 分析漏洞信息和 POC 代码
- 📝 **报告生成** - 生成结构化的 Markdown 分析报告
- 🔔 **实时通知** - 支持飞书等 Webhook 实时通知
- 🎯 **风险评估** - 自动评估漏洞风险等级和投毒风险
- 🔄 **多引擎搜索** - 支持多个 SearXNG 实例并发搜索，自动故障转移

## 📦 快速开始

### 方式一：GitHub Actions 部署（推荐）

#### 1. Fork 本仓库到你的 GitHub 账号

#### 2. 配置 Secrets

在仓库 Settings → Secrets and variables → Actions 中添加以下配置：

| Secret 名称 | 说明 | 是否必需 |
|------------|------|---------|
| `WEBHOOK_URL` | 飞书机器人 Webhook 地址 | 启用通知时必需 |
| `GPT_SERVER_URL` | GPT API 服务地址 | 启用 GPT 分析时必需 |
| `GPT_API_KEY` | GPT API 密钥 | 启用 GPT 分析时必需 |
| `GPT_MODEL` | GPT 模型名称（默认：gemini-2.0-flash） | 可选 |
| `GH_TOKEN` | GitHub Personal Access Token | 可选，推荐配置 |

#### 3. GitHub Token 配置（重要）

GitHub API 调用频率限制对比：

| 配置方式 | API 限制 | 推荐度 | 说明 |
|---------|---------|--------|------|
| 未配置 | 60次/小时 | ❌ | 容易触发限制 |
| GITHUB_TOKEN | 1000次/小时 | ✅ | Actions 自动提供 |
| GH_TOKEN | 5000次/小时 | ⭐ | 推荐配置 |

**配置 GH_TOKEN 步骤：**
1. 访问 [GitHub Settings → Tokens](https://github.com/settings/tokens)
2. 点击 "Generate new token (classic)"
3. 选择权限：`public_repo`（读取公共仓库）
4. 复制生成的 token，添加到仓库 Secrets 中

#### 4. 配置功能开关

编辑 `config.py` 文件中的功能开关：

```python
ENABLE_NOTIFY = True          # 是否启用通知功能
NOTIFY_TYPE = 'feishu'        # 通知类型（飞书）
ENABLE_GPT = True             # 是否启用 GPT 分析
GPT_MODEL = 'gemini-2.0-flash'  # GPT 模型名称
ENABLE_SEARCH = True          # 是否启用漏洞信息搜索
ENABLE_EXTENDED = True        # 是否启用扩展搜索
```

#### 5. 启动自动监控

- 工作流会自动每小时执行一次
- 也可以在 Actions 页面手动触发
- 修改执行频率：编辑 `.github/workflows/monitor.yml` 中的 cron 表达式

```yaml
on:
  schedule:
    - cron: '0 * * * *'  # 每小时执行
``` 

### 方式二：本地部署

#### 1. 克隆仓库

```bash
git clone https://github.com/yourusername/VulnWatchdog.git
cd VulnWatchdog
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
```

#### 3. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 文件，配置必要的参数
```

主要配置项：

```bash
# 通知配置
WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/xxx

# GPT 配置
GPT_SERVER_URL=https://api.openai.com/v1/chat/completions
GPT_API_KEY=your-api-key
GPT_MODEL=gemini-2.0-flash

# 搜索引擎配置（多引擎用逗号分隔）
SEARXNG_URLS=http://engine1/search,http://engine2/search

# GitHub Token（推荐配置，5000次/小时）
GH_TOKEN=ghp_your_github_token
```

#### 4. 配置功能开关

编辑 `config.py` 文件，根据需要开启功能。

#### 5. 运行程序

```bash
python main.py
```

## 📊 输出说明

### 分析报告结构

报告以 Markdown 格式生成，包含以下关键信息：

| 字段 | 说明 | 示例 |
|------|------|------|
| name | 漏洞名称 | CVE-2024-1234-应用名-漏洞类型 |
| type | 漏洞类型 | 命令注入、SQL注入、XSS等 |
| app | 受影响应用 | WordPress、Apache等 |
| risk | 风险等级与影响 | 高危，可能导致远程代码执行 |
| version | 受影响版本 | <= 1.2.3 |
| condition | 利用条件 | 需要认证/无需认证 |
| poc_available | POC 可用性 | 是/否 |
| poison | 投毒风险评估 | 90% |
| markdown | 详细分析内容 | Markdown 格式的完整分析 |

### 报告存储

- **路径**: `data/markdown/{cve_id}-{repo_name}.md`
- **索引**: 自动生成按日期组织的索引文件
- **更新**: 每次运行自动更新和提交

### 通知推送

支持通过 Webhook 实时推送分析结果，详见 [NOTIFY.md](NOTIFY.md)

## 📁 项目结构

```
VulnWatchdog/
├── main.py                    # 主程序入口
├── config.py                  # 配置管理
├── requirements.txt           # 依赖列表
│
├── libs/                      # 核心库
│   ├── utils.py              # 工具函数
│   ├── webhook.py            # Webhook 通知
│   ├── search_engines.py    # 多引擎搜索管理
│   └── default_search_engines.json  # 默认搜索引擎配置
│
├── models/                    # 数据模型
│   └── models.py             # CVE、仓库数据模型
│
├── tools/                     # 工具脚本
│   └── generate_indexes.py  # 生成索引和 README
│
├── data/                      # 数据存储
│   └── markdown/             # CVE 分析报告
│       ├── 2024-11/          # 按月份组织
│       └── 2024-12/
│
├── template/                  # 模板文件
│   ├── feishu.json           # 飞书通知模板
│   ├── custom.json           # 自定义通知模板
│   └── report.md             # 分析报告模板
│
└── .github/workflows/         # GitHub Actions
    ├── monitor.yml           # 自动监控工作流
    └── reorganize.yml        # 目录整理工作流
```

## 🔧 配置说明

### 功能开关（config.py）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `ENABLE_NOTIFY` | True | 是否启用通知功能 |
| `NOTIFY_TYPE` | 'feishu' | 通知类型（目前支持飞书） |
| `ENABLE_GPT` | True | 是否启用 GPT 分析 |
| `GPT_MODEL` | 'gemini-2.0-flash' | GPT 模型名称 |
| `ENABLE_SEARCH` | True | 是否启用漏洞信息搜索 |
| `ENABLE_EXTENDED` | True | 是否启用扩展搜索 |
| `ENABLE_UPDATE_CHECK` | True | 是否启用仓库更新检测 |

### 环境变量（.env）

完整配置说明请参考 `.env.example` 文件。

## 🛠️ 开发计划

- [x] 优化配置管理
- [x] 投毒风险评估
- [x] 多引擎搜索支持
- [x] GitHub Token 三级优先级
- [ ] 补充单元测试
- [ ] 支持更多通知渠道

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

**PR 提交前请确保：**
1. 代码风格符合项目规范
2. 添加必要的测试用例
3. 更新相关文档

## 📄 许可证

MIT License

## 🙏 致谢

- [Poc-Monitor](https://github.com/sari3l/Poc-Monitor) - 提供项目思路
- [SearXNG](https://github.com/searxng/searxng) - 提供搜索引擎支持

---

如有问题，欢迎提交 [Issue](https://github.com/yourusername/VulnWatchdog/issues)

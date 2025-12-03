# 消息通知模板说明

本文档说明如何配置和自定义 VulnWatchdog 的消息通知模板。

## 📋 快速开始

### 1. 配置通知

在 `.env` 文件中配置：

```bash
# 通知类型
NOTIFY_TYPE=feishu

# Webhook URL
WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/your-webhook-id
```

在 `config.py` 中启用：

```python
ENABLE_NOTIFY = True
```

### 2. 自定义模板

模板文件位于 `template/` 目录：
- `feishu.json` - 飞书通知模板
- `custom.json` - 自定义通知模板

## 🔤 模板变量

### CVE 漏洞信息

| 变量 | 说明 | 示例 |
|------|------|------|
| `{cve.title}` | CVE 标题 | CVE-2024-1234 |
| `{cve.description}` | CVE 描述 | 漏洞详细描述 |
| `{cve.published}` | 发布时间 | 2024-01-01T00:00:00Z |
| `{cve.lastModified}` | 最后修改时间 | 2024-01-02T00:00:00Z |
| `{cve.severity}` | 严重等级 | HIGH, MEDIUM, LOW |
| `{cve.cvssMetricV31}` | CVSS v3.1 评分 | 详见数据结构 |
| `{cve.references}` | 参考链接列表 | 详见数据结构 |

### 仓库信息

| 变量 | 说明 | 示例 |
|------|------|------|
| `{repo.name}` | 仓库名称 | CVE-2024-1234-POC |
| `{repo.full_name}` | 完整仓库名 | username/repo |
| `{repo.description}` | 仓库描述 | POC for CVE-2024-1234 |
| `{repo.html_url}` | 仓库 URL | https://github.com/... |
| `{repo.pushed_at}` | 最后推送时间 | 2024-01-01T00:00:00Z |
| `{repo.action_log}` | 操作类型 | new / update |

### GPT 分析结果

| 变量 | 说明 | 示例 |
|------|------|------|
| `{gpt.name}` | 漏洞名称 | CVE-2024-1234-WordPress-命令注入 |
| `{gpt.type}` | 漏洞类型 | 命令注入、SQL注入、XSS等 |
| `{gpt.app}` | 受影响应用 | WordPress |
| `{gpt.risk}` | 风险等级 | 高危，可能导致远程代码执行 |
| `{gpt.version}` | 受影响版本 | <= 6.4.2 |
| `{gpt.condition}` | 利用条件 | 需要管理员权限 |
| `{gpt.poc_available}` | POC 可用性 | 是 / 否 |
| `{gpt.poison}` | 投毒风险 | 90% |
| `{gpt.markdown}` | 详细分析 | Markdown 格式的完整分析 |
| `{gpt.cve_id}` | CVE 编号 | CVE-2024-1234 |
| `{gpt.repo_name}` | 仓库全名 | username/repo |
| `{gpt.repo_url}` | 仓库 URL | https://github.com/... |
| `{gpt.cve_url}` | CVE 详情页 | https://nvd.nist.gov/vuln/detail/... |
| `{gpt.action_log}` | 操作日志 | new / update |
| `{gpt.git_url}` | 项目地址 | GitHub Actions 部署时可用 |

## 📊 完整数据结构

### CVE 数据结构

```json
{
  "cve": {
    "title": "CVE-2024-1234",
    "description": {
      "value": "漏洞详细描述内容..."
    },
    "published": "2024-01-01T00:00:00.000Z",
    "lastModified": "2024-01-02T00:00:00.000Z",
    "severity": "HIGH",
    "cvssMetricV31": [
      {
        "cvssData": {
          "baseScore": 9.8,
          "baseSeverity": "CRITICAL"
        }
      }
    ],
    "references": [
      {
        "url": "https://example.com/advisory",
        "source": "vendor"
      }
    ]
  }
}
```

**更多字段参考**: [CVE API 文档](https://cve.circl.lu/api/)

### 仓库数据结构

```json
{
  "repo": {
    "id": 123456789,
    "name": "CVE-2024-1234-POC",
    "full_name": "username/CVE-2024-1234-POC",
    "html_url": "https://github.com/username/CVE-2024-1234-POC",
    "description": "POC for CVE-2024-1234",
    "pushed_at": "2024-01-01T00:00:00Z",
    "action_log": "new"
  }
}
```

**更多字段参考**: [GitHub API 文档](https://docs.github.com/rest/repos)

### GPT 分析数据结构

```json
{
  "gpt": {
    "name": "CVE-2024-1234-WordPress-命令注入",
    "type": "命令注入",
    "app": "WordPress",
    "risk": "高危，可能导致远程代码执行",
    "version": "<= 6.4.2",
    "condition": "需要管理员权限",
    "poc_available": "是",
    "poison": "90%",
    "markdown": "## 漏洞分析\n\n详细的漏洞分析内容...",
    "cve_id": "CVE-2024-1234",
    "repo_name": "username/CVE-2024-1234-POC",
    "repo_url": "https://github.com/username/CVE-2024-1234-POC",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    "action_log": "new",
    "git_url": "https://github.com/your/VulnWatchdog"
  }
}
```

## 💡 模板示例

### 飞书卡片模板（feishu.json）

飞书通知使用交互式卡片格式，包含以下区域：

**1. 标题区域**
```json
{
  "tag": "div",
  "text": {
    "content": "**{gpt.name}**",
    "tag": "lark_md"
  }
}
```

**2. 基本信息区域**
- CVE 编号
- 漏洞类型
- 受影响应用
- 操作类型（新增/更新）

**3. 风险评估区域**
- 风险等级
- 受影响版本
- 利用条件
- POC 可用性
- 投毒风险

**4. 链接区域**
- CVE 详情链接
- GitHub 仓库链接
- 分析报告链接

### 自定义模板创建步骤

1. **复制现有模板**
   ```bash
   cp template/feishu.json template/custom.json
   ```

2. **修改模板内容**
   - 使用 `{变量名}` 格式引用变量
   - 支持嵌套变量访问，如 `{cve.description.value}`
   - 可以添加自定义文本和格式

3. **配置使用自定义模板**
   ```bash
   # .env
   NOTIFY_TYPE=custom
   ```

### 模板变量使用示例

```json
{
  "title": "漏洞通知：{gpt.name}",
  "content": {
    "cve_id": "{gpt.cve_id}",
    "type": "{gpt.type}",
    "app": "{gpt.app}",
    "risk": "{gpt.risk}",
    "version": "{gpt.version}",
    "condition": "{gpt.condition}",
    "poc": "{gpt.poc_available}",
    "poison": "{gpt.poison}",
    "links": {
      "cve": "{gpt.cve_url}",
      "repo": "{gpt.repo_url}",
      "report": "{gpt.git_url}/blob/main/data/markdown/{gpt.cve_id}-{repo.name}.md"
    }
  }
}
```

## 🔧 高级用法

### 条件显示

根据不同的操作类型（new/update）显示不同内容：

```json
{
  "action": "{repo.action_log}",
  "message": "发现{repo.action_log}漏洞"
}
```

### 时间格式化

所有时间字段都是 ISO 8601 格式，可以在模板中直接使用：

```json
{
  "published": "{cve.published}",
  "updated": "{cve.lastModified}"
}
```

### Markdown 内容

`{gpt.markdown}` 包含完整的 Markdown 格式分析内容，可以直接嵌入支持 Markdown 的通知系统。

## 📚 参考资料

- [飞书机器人文档](https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN)
- [CVE API 文档](https://cve.circl.lu/api/)
- [GitHub REST API](https://docs.github.com/rest)

## ❓ 常见问题

**Q: 如何测试自定义模板？**

A: 修改模板后，本地运行 `python main.py` 测试，或在 Actions 中手动触发工作流。

**Q: 模板变量不存在会怎样？**

A: 如果某个变量不存在（如未启用 GPT 分析时的 `gpt.*` 变量），会显示为空字符串。

**Q: 如何支持其他通知平台？**

A: 参考 `template/feishu.json` 创建新模板，并在 `config.py` 中配置 `NOTIFY_TYPE`。

**Q: 可以在模板中使用条件判断吗？**

A: 目前仅支持简单的变量替换，不支持复杂的条件判断逻辑。建议在 `libs/webhook.py` 中实现条件逻辑。

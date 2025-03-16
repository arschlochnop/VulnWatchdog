# VulnWatchdog

VulnWatchdog 是一个自动化的漏洞监控和分析工具。它可以监控 GitHub 上的 CVE 相关仓库,获取漏洞信息和 POC 代码,并使用 GPT 进行智能分析,生成详细的分析报告。

## 主要功能

- 🔍 自动监控 GitHub 上的 CVE 相关仓库
- 📊 获取并解析 CVE 漏洞详细信息  
- 🤖 使用 GPT 智能分析漏洞信息和 POC 代码
- 📝 生成结构化的分析报告
- 🔔 支持 Webhook 实时通知
- 🎯 漏洞评分系统
- 🔒 投毒风险评估

## 部署说明

### GitHub Actions 自动部署

本项目使用 GitHub Actions 实现自动化监控和分析。配置文件位于 `.github/monitor.yml`。

1. 配置项目action Settings -> Secrets 中添加以下 secrets敏感参数:

```yaml


# Webhook配置
WEBHOOK_URL: "your_webhook_url"

# GPT配置
GPT_SERVER_URL: "your_gpt_server_url"
GPT_API_KEY: "your_gpt_api_key"


# 搜索配置
SEARXNG_URL: "your_searxng_url"
```

2. 配置config.py中功能开关

```yaml
# 是否启用通知功能
ENABLE_NOTIFY=True

# 通知类型,目前支持飞书(feishu),其他可参考飞书模板 template/feishu.json
NOTIFY_TYPE='feishu'

# 是否启用GPT功能进行漏洞分析
ENABLE_GPT=True

# GPT模型名称,使用Gemini 2.0 Flash版本
GPT_MODEL='gemini-2.0-flash'

# 是否启用漏洞信息搜索功能，需启用GPT分析
ENABLE_SEARCH=True

# 是否启用扩展搜索功能
ENABLE_EXTENDED=True

```

3. Actions 会按以下时间表自动运行:
- 每小时执行一次漏洞监控
- 可以在 Actions 页面手动触发

4. 监控结果会:
- 保存到 `data/markdown/` 目录
- 通过配置的 Webhook 发送通知
- 自动提交更新到仓库

5. 如需修改运行计划,编辑 `.github/monitor.yml` 中的 cron 表达式:
```yaml
on:
  schedule:
    - cron: '0 * * * *'  # 每小时运行
``` 

## 本地部署说明

1. 克隆仓库
```bash
git clone https://github.com/yourusername/VulnWatchdog.git
cd VulnWatchdog
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 配置环境变量
```bash
cp .env.copy .env
# 编辑 .env 文件,配置必要的敏感参数
# 编辑config.py文件,配置功能开关
```

4. 运行程序
```bash 
python main.py
```

## 输出说明

### 分析报告

分析报告以 Markdown 格式输出,包含以下字段:

```json
{
    "name": "漏洞名称",
    "type": "漏洞类型",
    "app": "受影响应用", 
    "risk": "风险等级",
    "version": "受影响版本",
    "condition": "触发条件",
    "poc_available": "是否有可用POC",
    "poison": "投毒风险概率",
    "markdown": "详细分析说明"
}
```

### 报告存储位置

分析报告保存在 `data/markdown/` 目录下,文件名格式为:
`{cve_id}-{repo_name}.md`

## 消息通知

消息通知模板请参考[NOTIFY.md](NOTIFY.md)

## 项目结构

```
VulnWatchdog/
├── main.py              # 主程序入口
├── config.py            # 配置管理
├── libs/               
│   ├── utils.py        # 工具函数
│   └── webhook.py      # Webhook 通知
├── models/
│   └── models.py       # 数据模型
├── data/
|    └── markdown/       # 分析报告存储
└── template/           # 模板
     ├── feishu.json    # 飞书消息模板
     ├── custom.json    # 自定义消息模板
     └── report.md      # 分析报告模板
```

## 开发计划

- [x] 优化配置管理
- [ ] 补充单元测试
- [ ] 完善文档
- [x] 投毒风险评估

## 贡献指南

欢迎提交 Issue 和 Pull Request。在提交 PR 前,请确保:

1. 代码风格符合项目规范
2. 添加必要的测试用例
3. 更新相关文档

## 许可证

MIT License

## 联系方式

如有问题,请提交 Issue

致谢
- 感谢 [Poc-Monitor](https://github.com/sari3l/Poc-Monitor) 项目提供的思路
- 感谢 [SearXNG](https://github.com/searxng/searxng) 项目提供的搜索引擎

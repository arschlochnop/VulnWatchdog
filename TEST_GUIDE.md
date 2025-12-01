# 本地测试指南

本文档提供 VulnWatchdog 项目的本地测试方法，用于验证新功能的稳定性。

## 📋 测试目标

验证以下新增功能是否稳定运行：

1. ✅ **监控模块集成** (`libs/monitor.py`)
   - 运行时统计和性能指标收集
   - 错误追踪和健康状态检查

2. ✅ **临时文件清理机制**
   - 自动清理临时克隆目录
   - 防止磁盘空间累积

3. ✅ **GPT解析鲁棒性**
   - 支持多种JSON格式
   - 智能提取和错误恢复

4. ✅ **Commit SHA更新检测**
   - 精确判断仓库是否更新
   - 避免重复处理

## 🚀 快速开始

### 方法一：使用测试脚本（推荐）

```bash
# 1. 运行测试脚本
./test_local.sh

# 脚本会自动：
# - 检查 Python 环境
# - 创建/激活虚拟环境
# - 安装依赖
# - 检查配置文件
# - 运行测试程序
# - 显示测试结果和监控摘要
```

### 方法二：手动运行

```bash
# 1. 激活虚拟环境
source .venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境（可选）
cp .env.test .env
# 编辑 .env 文件，配置 API 密钥

# 4. 运行测试程序
python test_main.py
```

## ⚙️ 配置说明

### 测试级别

根据你的需求选择不同的测试配置：

#### 1️⃣ 最小测试（无需外部服务）

**适用场景：**
- 测试基础功能（GitHub 搜索、数据库存储）
- 测试监控模块
- 测试临时文件清理机制

**配置方法：**

在 `config.py` 中设置：

```python
ENABLE_GPT = False        # 禁用 GPT 分析
ENABLE_SEARCH = False     # 禁用搜索功能
ENABLE_NOTIFY = False     # 禁用通知功能
ENABLE_UPDATE_CHECK = True  # 启用更新检测
```

**优点：**
- 无需配置 API 密钥
- 快速验证核心逻辑
- 适合开发调试

---

#### 2️⃣ 中级测试（需要 GPT API）

**适用场景：**
- 测试 GPT 分析功能
- 测试 GPT 解析鲁棒性
- 测试完整的数据流

**配置方法：**

1. 在 `config.py` 中设置：
```python
ENABLE_GPT = True         # 启用 GPT 分析
ENABLE_SEARCH = False     # 可选：启用搜索
ENABLE_NOTIFY = False     # 禁用通知
ENABLE_UPDATE_CHECK = True
```

2. 在 `.env` 中配置：
```bash
GPT_SERVER_URL=https://your-gpt-server/v1/chat/completions
GPT_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**优点：**
- 测试 GPT 分析流程
- 验证解析鲁棒性

---

#### 3️⃣ 完整测试（需要所有服务）

**适用场景：**
- 完整功能测试
- 上线前验证
- 模拟生产环境

**配置方法：**

1. 在 `config.py` 中启用所有功能：
```python
ENABLE_GPT = True
ENABLE_SEARCH = True
ENABLE_NOTIFY = True
ENABLE_UPDATE_CHECK = True
ENABLE_EXTENDED = False  # 测试时建议关闭扩展搜索
```

2. 在 `.env` 中配置所有参数：
```bash
# GPT 配置
GPT_SERVER_URL=https://your-gpt-server/v1/chat/completions
GPT_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Webhook 配置
WEBHOOK_URL=https://xxx.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# 搜索引擎配置
SEARXNG_URL=https://your-searxng-instance

# GitHub Token（可选，提升API限制）
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 📊 测试输出说明

### 1. 控制台日志

测试运行时会显示详细的日志信息：

```
=========================================
开始本地测试
=========================================
运行参数:
  DEBUG模式: INFO
  GPT分析: 启用
  搜索功能: 启用
  扩展搜索: 禁用
  更新检测: 启用
  通知功能: 禁用
=========================================

[1/3] 处理CVE: CVE-2024-XXXXX
开始处理仓库: user/repo
发现新仓库: https://github.com/user/repo
获取POC代码: https://github.com/user/repo
...
```

### 2. 监控摘要

测试完成后会显示监控摘要：

```
============================================================
运行监控摘要
============================================================
运行时长: 2分30秒

发现统计:
  CVE总数: 10
  仓库总数: 15

处理统计:
  新仓库: 2
  更新仓库: 1
  跳过（无更新）: 12
  成功: 3
  失败: 0
  成功率: 100.0%

GitHub API统计:
  调用次数: 15
  失败次数: 0
  成功率: 100.0%

GPT分析统计:
  调用次数: 3
  失败次数: 0
  解析失败: 0
  成功率: 100.0%

更新检测统计:
  检测次数: 13
  发现更新: 1
  更新率: 7.7%

临时文件清理:
  创建: 3
  清理: 3
  失败: 0
  清理率: 100.0%

错误统计:
  总错误数: 0
============================================================
```

### 3. 生成的文件

#### test_monitor_result.json

包含详细的监控数据（JSON格式）：

```json
{
  "runtime": {
    "seconds": 150.5,
    "formatted": "2分30秒"
  },
  "discovery": {
    "total_cves": 10,
    "total_repos": 15
  },
  "processing": {
    "new": 2,
    "updated": 1,
    "skipped": 12,
    "success": 3,
    "failed": 0,
    "success_rate": "100.0%"
  },
  "errors": {
    "total": 0,
    "by_type": {},
    "recent": []
  }
}
```

#### data/{YEAR}/{CVE-ID}-{REPO}.md

生成的漏洞分析报告，例如：

```
data/
└── 2024/
    ├── CVE-2024-12345-user_repo.md
    └── CVE-2024-67890-another_repo.md
```

---

## 🔍 验证检查点

测试完成后，检查以下关键指标：

### ✅ 核心功能验证

- [ ] **GitHub 搜索**：成功找到 CVE 和仓库
- [ ] **数据库存储**：成功保存 CVE 和仓库信息
- [ ] **更新检测**：正确跳过无更新的仓库
- [ ] **GPT 分析**：成功调用并解析 GPT 结果
- [ ] **报告生成**：在 `data/` 目录生成 Markdown 报告

### ✅ 监控模块验证

- [ ] **统计准确**：监控数据与实际处理数量一致
- [ ] **成功率**：处理成功率 >= 90%
- [ ] **错误追踪**：错误被正确记录
- [ ] **健康检查**：健康状态为 `healthy` 或 `warning`

### ✅ 临时文件清理验证

- [ ] **零残留**：`/tmp` 目录下无 `vulnwatchdog_*` 残留
- [ ] **清理率**：临时文件清理率 = 100%

检查方法：
```bash
# 查看临时目录
ls -la /tmp | grep vulnwatchdog

# 应该没有输出，或显示：
# (无结果)
```

### ✅ GPT 解析鲁棒性验证

如果启用了 GPT 功能：

- [ ] **解析成功**：GPT 调用成功率 >= 90%
- [ ] **格式支持**：能正确解析各种 JSON 格式
- [ ] **错误恢复**：解析失败时有详细错误日志

---

## 🐛 常见问题

### 1. GitHub API 限流

**现象：**
```
GitHub API 失败次数较多
```

**解决方法：**
- 在 `.env` 中配置 `GITHUB_TOKEN`
- 或者减少测试数量，等待限流重置（1小时）

---

### 2. GPT 调用失败

**现象：**
```
GPT分析失败
```

**检查：**
1. 确认 `.env` 中的 `GPT_SERVER_URL` 和 `GPT_API_KEY` 正确
2. 检查网络连接
3. 查看详细错误日志

---

### 3. 临时文件未清理

**现象：**
```
发现 X 个临时目录（可能需要手动清理）
```

**原因：**
- 程序异常退出，未执行 `finally` 清理
- 系统权限问题

**手动清理：**
```bash
rm -rf /tmp/vulnwatchdog_*
```

---

### 4. 数据库锁定

**现象：**
```
database is locked
```

**解决方法：**
```bash
# 关闭所有占用数据库的进程
# 或删除测试数据库重新开始
rm vulns.db
```

---

## 📈 性能基准

以下是正常运行的性能基准（供参考）：

| 指标 | 预期值 | 说明 |
|------|--------|------|
| 处理成功率 | ≥ 90% | 偶尔的网络问题可接受 |
| GitHub API 成功率 | ≥ 95% | 避免频繁限流 |
| GPT 调用成功率 | ≥ 90% | GPT 服务偶尔不稳定 |
| 临时文件清理率 | 100% | 必须完全清理 |
| 平均处理时间 | 30-60秒/仓库 | 取决于网络和 GPT 速度 |

---

## 🎯 下一步

### 测试通过后

1. **运行完整版本**
   ```bash
   python main.py
   ```

2. **推送到 GitHub，触发 Actions 测试**
   ```bash
   git add .
   git commit -m "测试: 验证新功能稳定性"
   git push
   ```

3. **查看 GitHub Actions 运行结果**
   - 前往仓库的 Actions 页面
   - 检查是否成功运行

### 测试失败时

1. **检查日志**
   - 查找 `ERROR` 和 `WARNING` 日志
   - 定位具体失败原因

2. **查看监控数据**
   ```bash
   cat test_monitor_result.json | jq '.errors'
   ```

3. **调试模式**
   - 在 `.env` 中设置 `DEBUG=true`
   - 重新运行，查看详细日志

---

## 💡 提示

1. **首次测试建议**：使用最小配置，确保基础功能正常
2. **逐步启用功能**：一次启用一个功能，便于定位问题
3. **保存测试结果**：保留 `test_monitor_result.json` 便于对比
4. **清理测试数据**：测试完成后可以删除 `data/` 和 `vulns.db`

---

## 📞 获取帮助

如果遇到问题：

1. 查看项目文档：`docs/`
2. 检查 GitHub Issues
3. 查看优化文档：`docs/archive/OPTIMIZATION_*.md`

---

## 📝 测试检查清单

```
□ 环境准备
  □ Python 3.x 已安装
  □ 虚拟环境已创建
  □ 依赖已安装

□ 配置检查
  □ 功能开关已设置（config.py）
  □ API 密钥已配置（.env，如需）

□ 运行测试
  □ 测试脚本执行成功
  □ 无严重错误

□ 结果验证
  □ 监控摘要正常
  □ 成功率达标
  □ 临时文件已清理
  □ 报告已生成

□ 准备上线
  □ 本地测试通过
  □ 推送到 GitHub
  □ Actions 测试通过
```

---

**祝测试顺利！** 🎉

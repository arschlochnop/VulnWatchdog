# VulnWatchdog 本地测试指南

## 📋 测试前准备

### 1. 环境检查

```bash
# 确认在项目目录
cd /Users/dm/data/share/code/VulnWatchdog

# 激活虚拟环境
source .venv/bin/activate

# 验证Python版本
python --version
# 预期: Python 3.10+

# 检查依赖是否安装
pip list | grep -E "requests|sqlalchemy"
```

### 2. 配置检查

```bash
# 查看当前配置
cat config.py | grep "ENABLE"
```

**关键配置说明:**
- `ENABLE_GPT=True` - 需要配置GPT API（可暂时关闭测试其他功能）
- `ENABLE_UPDATE_CHECK=True` - 更新检测开关（新功能）
- `ENABLE_NOTIFY=True` - 通知功能（需要webhook配置）
- `ENABLE_SEARCH=True` - 搜索功能（需要SearXNG）
- `ENABLE_EXTENDED=True` - 扩展搜索（慎用，API调用多）

---

## 🧪 测试优化功能

### 测试1: 更新检测逻辑 ✅

**测试目的:** 验证基于commit SHA的更新检测是否正常工作

```bash
# 运行更新检测逻辑测试
python test_update_logic.py
```

**预期输出:**
```
🧪 测试更新检测逻辑

✓ ENABLE_UPDATE_CHECK 配置: True

✓ 数据库字段检查:
  github_id: xxx
  url: https://github.com/...
  repo_pushed_at: 2025-03-14T15:44:54Z
  latest_commit_sha: None  ← 新字段
  action_log: new

📊 数据统计:
  总记录数: 7680
  已有SHA: 0  ← 需要运行迁移脚本
  缺少SHA: 7680

✅ 测试验证完成
```

**如果出错:**
- 检查数据库文件是否存在: `ls -la vulns.db`
- 检查字段是否添加: `sqlite3 vulns.db ".schema repositories"`

---

### 测试2: 临时文件清理机制 🧹

**测试目的:** 验证临时目录清理逻辑

```bash
# 运行清理机制测试
python test_cleanup.py
```

**预期输出:**
```
🧪 测试临时仓库清理机制

📊 测试前状态:
  /tmp 中 vulnwatchdog_* 目录数: 0

💡 关键优化点:
  ✅ 使用 try-finally 确保清理
  ✅ 浅克隆 (--depth 1) 减少下载量
  ✅ 超时保护 (60秒)
  ✅ 目录命名前缀 (vulnwatchdog_) 便于识别

📊 预期结果:
  处理完成后: /tmp 中 vulnwatchdog_* 目录数 = 0
  ✅ 零累积，完全避免磁盘占用问题

✅ 测试验证完成
```

**手动验证:**
```bash
# 检查/tmp目录（应该为空）
ls /tmp/vulnwatchdog_* 2>/dev/null
# 预期: 无输出（或显示 "No such file or directory"）
```

---

### 测试3: GPT响应解析鲁棒性 🔧

**测试目的:** 验证多格式JSON解析能力

```bash
# 运行GPT解析测试
python test_gpt_parsing.py
```

**预期输出:**
```
🧪 测试GPT响应解析鲁棒性

测试 1: 标准markdown格式 (小写json)
  输入: '```json\n{\n    "name": "CVE-2025-12345"...'
  ✅ 解析成功
  结果: {'name': 'CVE-2025-12345', 'type': 'SQL注入'}

[...其他7个测试...]

============================================================
测试总结:
  总计: 8 个测试
  通过: 8 个
  失败: 0 个
  成功率: 100.0%

✅ 所有测试通过！
```

**如果有失败:**
- 检查Python版本（需要3.7+支持f-string）
- 查看具体失败的测试用例

---

## 🔍 测试完整流程（模拟真实运行）

### 方案A: 简化测试（推荐，无需API配置）

**步骤1: 关闭GPT和搜索功能**

```bash
# 编辑config.py
cat > config_test.py << 'EOF'
# 测试模式配置
ENABLE_GPT = False  # 关闭GPT分析
ENABLE_SEARCH = False  # 关闭搜索
ENABLE_NOTIFY = False  # 关闭通知
ENABLE_EXTENDED = False  # 关闭扩展搜索
ENABLE_UPDATE_CHECK = True  # 保持更新检测开启
EOF
```

**步骤2: 备份原配置并使用测试配置**

```bash
# 备份原配置
cp config.py config.py.bak

# 修改config.py中的开关
# 手动编辑或使用sed
sed -i.backup 's/ENABLE_GPT=True/ENABLE_GPT=False/' config.py
sed -i.backup 's/ENABLE_SEARCH=True/ENABLE_SEARCH=False/' config.py
sed -i.backup 's/ENABLE_NOTIFY=True/ENABLE_NOTIFY=False/' config.py
sed -i.backup 's/ENABLE_EXTENDED=True/ENABLE_EXTENDED=False/' config.py
```

**步骤3: 运行主程序**

```bash
# 查看将要使用的配置
python main.py 2>&1 | head -20
```

**预期日志:**
```
运行参数:
  运行模式: INFO
  GPT 开关: 禁用  ← 已关闭
  搜索开关: 禁用  ← 已关闭
  扩展搜索开关: 禁用  ← 已关闭
  更新检测开关: 启用  ← 新功能
  通知开关: 禁用  ← 已关闭
  通知类型: feishu

开始搜索CVE: CVE-20
GitHub搜索到 30 个仓库
找到CVE: CVE-2025-XXXXX
...
```

**步骤4: 观察更新检测逻辑**

```bash
# 过滤关键日志
python main.py 2>&1 | grep -E "仓库已存在|仓库无更新|仓库有更新|发现新仓库"
```

**预期日志示例:**
```
仓库已存在: https://github.com/xxx/CVE-2025-XXXXX
仓库无更新 (SHA相同: cd287a6c...),跳过处理  ← 新逻辑生效
```

**步骤5: 恢复原配置**

```bash
# 恢复原配置
mv config.py.bak config.py
```

---

### 方案B: 完整测试（需要API配置）

**前提条件:**
- ✅ 已配置GPT API（环境变量 `GPT_API_KEY` 和 `GPT_SERVER_URL`）
- ✅ 已配置SearXNG（环境变量 `SEARXNG_URL`）
- ⚠️ 注意API调用成本

**步骤1: 检查环境变量**

```bash
# 检查必需的环境变量
echo "GPT_API_KEY: ${GPT_API_KEY:0:20}..."  # 只显示前20字符
echo "GPT_SERVER_URL: $GPT_SERVER_URL"
echo "SEARXNG_URL: $SEARXNG_URL"
```

**步骤2: 小规模测试**

创建测试脚本：

```bash
cat > test_single_cve.py << 'EOF'
#!/usr/bin/env python3
"""测试单个CVE处理流程"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from main import process_cve
from models.models import get_db

# 使用一个已知的小型仓库测试
test_repo = {
    'id': 999999999,  # 虚构ID，避免冲突
    'name': 'test-poc',
    'full_name': 'test/test-poc',
    'html_url': 'https://github.com/你选择的测试仓库',
    'description': 'Test POC',
    'pushed_at': '2025-11-27T10:00:00Z'
}

engine = get_db()
result = process_cve('CVE-2025-XXXXX', test_repo, engine)
print(f"\n测试结果: {result}")
EOF

chmod +x test_single_cve.py
python test_single_cve.py
```

**步骤3: 监控资源使用**

在另一个终端监控：

```bash
# 监控临时目录
watch -n 2 'ls /tmp/vulnwatchdog_* 2>/dev/null | wc -l'

# 监控磁盘使用
watch -n 5 'df -h /tmp'

# 监控进程
watch -n 2 'ps aux | grep python | grep main.py'
```

**预期观察:**
- 临时目录数始终为 0 或 1（处理中）
- 处理完成后自动清理
- 磁盘使用稳定，不持续增长

---

## 🔧 数据迁移测试（首次部署）

**目的:** 为现有7680条记录填充commit SHA

**重要提示:** ⚠️ 此操作会调用7680次GitHub API，预计耗时10-15分钟

### 干运行（推荐先做）

修改迁移脚本，添加dry-run模式：

```bash
# 查看前10条需要迁移的记录
sqlite3 vulns.db "
SELECT id, url, latest_commit_sha
FROM repositories
WHERE latest_commit_sha IS NULL
LIMIT 10
"
```

### 正式迁移

```bash
# 运行迁移脚本
python scripts/migrate_commit_sha.py

# 或者后台运行并记录日志
nohup python scripts/migrate_commit_sha.py > migration.log 2>&1 &

# 查看进度
tail -f migration.log
```

**预期输出:**
```
🚀 开始迁移commit SHA数据...
📊 找到 7680 条需要迁移的记录

[1/7680] 处理仓库: https://github.com/...
  ✓ 填充SHA成功: cd287a6c...
[2/7680] 处理仓库: https://github.com/...
  ✓ 填充SHA成功: e4f92b1a...
...
  💤 暂停1秒 (已处理 10/7680)...
...

============================================================
📊 迁移完成统计:
  总计:   7680 条
  成功:   7650 条
  失败:   30 条
  成功率: 99.6%
============================================================

✅ 验证: 剩余 30 条记录未填充SHA
```

**验证迁移结果:**

```bash
# 检查填充情况
sqlite3 vulns.db "
SELECT
    COUNT(*) as total,
    COUNT(latest_commit_sha) as with_sha,
    COUNT(*) - COUNT(latest_commit_sha) as without_sha
FROM repositories
"
```

**预期输出:**
```
total|with_sha|without_sha
7680|7650|30
```

---

## 📊 验证优化效果

### 1. 验证更新检测逻辑

```bash
# 查看action_log分布
sqlite3 vulns.db "
SELECT action_log, COUNT(*)
FROM repositories
GROUP BY action_log
"
```

**优化前:**
```
new|7679
update|1
```

**优化后（随着时间推移）:**
```
new|7679
update|50+  ← 会逐渐增加
```

---

### 2. 验证临时文件清理

**测试前:**
```bash
# 统计/tmp目录大小
du -sh /tmp
```

**运行一次完整流程后:**
```bash
# 再次统计（应该没有明显增长）
du -sh /tmp

# 检查vulnwatchdog临时目录
ls /tmp/vulnwatchdog_* 2>/dev/null
# 预期: 无输出
```

---

### 3. 验证GPT解析改进

**查看日志:**
```bash
# 统计解析策略使用情况
grep "JSON解析成功" logs/*.log | grep -o "策略[0-9]" | sort | uniq -c
```

**预期输出:**
```
  1523 策略1  ← 大部分使用策略1（提取markdown）
   234 策略2  ← 少部分使用策略2（原始内容）
    12 策略3  ← 极少使用策略3（兼容旧逻辑）
```

**查看失败率:**
```bash
# 统计解析失败次数
grep "所有解析策略均失败" logs/*.log | wc -l

# 对比总调用次数
grep "请求GPT分析" logs/*.log | wc -l
```

---

## 🐛 常见问题排查

### 问题1: 提示"无法获取commit SHA"

**原因:**
- 网络连接问题
- GitHub API限流
- 仓库不存在或私有

**排查步骤:**
```bash
# 1. 测试网络连接
curl -I https://api.github.com

# 2. 检查API限流状态
curl https://api.github.com/rate_limit

# 3. 手动测试一个仓库
curl https://api.github.com/repos/N0c1or/CVE-2025-24813_POC/commits?per_page=1
```

**解决方案:**
- 添加GitHub Token认证（提升限制）
- 暂时关闭更新检测: `ENABLE_UPDATE_CHECK=False`
- 等待限流重置（每小时刷新）

---

### 问题2: 临时目录没有被清理

**排查步骤:**
```bash
# 查看是否有残留目录
ls -la /tmp/vulnwatchdog_*

# 查看进程是否卡住
ps aux | grep python | grep main.py

# 检查日志是否有异常
tail -100 logs/latest.log | grep -A5 "克隆仓库"
```

**可能原因:**
- 进程被强制终止（Ctrl+C），finally块未执行
- 权限问题（无法删除）
- 磁盘空间不足

**解决方案:**
```bash
# 手动清理
rm -rf /tmp/vulnwatchdog_*

# 检查磁盘空间
df -h /tmp

# 检查权限
ls -ld /tmp
```

---

### 问题3: GPT解析一直失败

**排查步骤:**
```bash
# 查看原始GPT返回内容
grep "原始内容:" logs/*.log | tail -5

# 检查GPT API配置
echo "GPT_SERVER_URL: $GPT_SERVER_URL"
echo "GPT_MODEL: $GPT_MODEL"
```

**可能原因:**
- GPT返回格式不是JSON
- GPT API配置错误
- Prompt设计问题

**解决方案:**
- 检查prompt是否要求JSON输出
- 验证GPT_MODEL支持JSON mode
- 查看具体失败的内容，调整解析策略

---

## 📝 测试检查清单

### 基础测试 ✅
- [ ] `test_update_logic.py` 通过
- [ ] `test_cleanup.py` 通过
- [ ] `test_gpt_parsing.py` 通过（8/8）
- [ ] 数据库字段 `latest_commit_sha` 存在

### 功能测试 ✅
- [ ] 更新检测正确跳过相同SHA的仓库
- [ ] 临时目录处理后自动清理
- [ ] GPT解析支持多种格式
- [ ] 日志输出详细且正确

### 性能测试 ✅
- [ ] 克隆速度提升（浅克隆生效）
- [ ] 磁盘占用稳定（不持续增长）
- [ ] 超时保护有效（60秒）

### 数据迁移 ✅（首次部署）
- [ ] 迁移脚本成功填充SHA
- [ ] 成功率 > 95%
- [ ] 数据库记录正确更新

---

## 🎯 推荐测试流程

**快速验证（5分钟）:**
```bash
# 1. 运行单元测试
python test_update_logic.py
python test_cleanup.py
python test_gpt_parsing.py

# 2. 检查数据库
sqlite3 vulns.db ".schema repositories" | grep latest_commit_sha
```

**完整测试（30分钟）:**
```bash
# 1. 单元测试（同上）
# 2. 数据迁移
python scripts/migrate_commit_sha.py

# 3. 简化流程测试（关闭GPT）
# 修改config.py关闭GPT和搜索
python main.py 2>&1 | tee test_run.log

# 4. 验证结果
grep -E "仓库已存在|无更新|有更新" test_run.log
ls /tmp/vulnwatchdog_* 2>/dev/null
```

**生产前测试（1小时+）:**
```bash
# 1-3同上
# 4. 完整流程测试（保持GPT开启）
python main.py

# 5. 监控资源使用
# 6. 验证生成的markdown报告质量
# 7. 检查README索引更新
```

---

**最后更新:** 2025-11-27
**版本:** 1.0

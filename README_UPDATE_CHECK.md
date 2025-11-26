# 仓库更新检测功能说明

## 📖 功能简介

基于 Git Commit SHA 的精确仓库更新检测机制，避免对未变化的POC仓库重复分析。

## 🚀 快速开始

### 1. 首次使用 - 数据迁移

为现有仓库记录填充commit SHA（只需执行一次）：

```bash
python scripts/migrate_commit_sha.py
```

**预计耗时:** 约10-15分钟（7680条记录）

### 2. 配置更新检测

**启用更新检测**（推荐，默认已启用）：
```python
# config.py
ENABLE_UPDATE_CHECK = True
```

**关闭更新检测**（跳过所有已存在仓库）：
```python
# config.py
ENABLE_UPDATE_CHECK = False
```

### 3. 运行程序

```bash
python main.py
```

程序启动时会显示配置状态：
```
运行参数:
  运行模式: INFO
  GPT 开关: 启用
  搜索开关: 启用
  扩展搜索开关: 启用
  更新检测开关: 启用  ← 新增
  通知开关: 启用
```

## 💡 工作原理

### 更新判断流程

```
搜索GitHub仓库
    ↓
检查数据库是否存在
    ↓
    ├─ 不存在 → 完整处理（新仓库）
    │             ├─ 克隆仓库
    │             ├─ GPT分析
    │             └─ 保存（action_log='new'）
    │
    └─ 已存在 → 获取最新commit SHA
                  ↓
                  ├─ SHA相同 → 跳过（无更新）
                  │
                  └─ SHA不同 → 更新处理
                                ├─ 重新克隆
                                ├─ 重新分析
                                └─ 更新记录（action_log='update'）
```

### 技术特点

- ✅ **无需clone判断** - 通过GitHub API获取SHA
- ✅ **精确可靠** - SHA基于Git原生机制，100%准确
- ✅ **性能高效** - 单次API调用，响应快速
- ✅ **资源节省** - 只对真正有更新的仓库重新分析

## 📊 使用效果

### 场景示例

**场景1: 仓库无更新**
```
2025-11-27 10:00:00 - INFO - 仓库已存在: https://github.com/N0c1or/CVE-2025-24813_POC
2025-11-27 10:00:01 - INFO - 仓库无更新 (SHA相同: cd287a6c...),跳过处理
```
**结果:** 跳过克隆和分析，节省时间和资源

---

**场景2: 仓库有更新**
```
2025-11-27 10:00:00 - INFO - 仓库已存在: https://github.com/N0c1or/CVE-2025-24813_POC
2025-11-27 10:00:01 - INFO - 仓库有更新 (旧SHA: cd287a6c... → 新SHA: e4f92b1a...)
2025-11-27 10:00:02 - INFO - 获取POC代码: https://github.com/N0c1or/CVE-2025-24813_POC
2025-11-27 10:00:15 - INFO - 请求GPT分析
2025-11-27 10:00:30 - INFO - 更新仓库信息成功 (SHA: e4f92b1a...)
```
**结果:** 重新分析并更新markdown报告

---

**场景3: 新仓库**
```
2025-11-27 10:00:00 - INFO - 发现新仓库: https://github.com/author/CVE-2025-XXXXX
2025-11-27 10:00:01 - INFO - 获取POC代码: https://github.com/author/CVE-2025-XXXXX
2025-11-27 10:00:15 - INFO - 请求GPT分析
2025-11-27 10:00:30 - INFO - 新增仓库信息成功 (SHA: a1b2c3d4...)
```
**结果:** 完整处理，生成新的分析报告

## 🔍 数据验证

### 检查SHA填充情况

```bash
sqlite3 vulns.db "
SELECT
    COUNT(*) as total,
    COUNT(latest_commit_sha) as with_sha,
    COUNT(*) - COUNT(latest_commit_sha) as without_sha
FROM repositories
"
```

**期望结果:**
```
total|with_sha|without_sha
7680|7680|0
```

### 检查更新记录

```bash
sqlite3 vulns.db "
SELECT action_log, COUNT(*)
FROM repositories
GROUP BY action_log
"
```

**示例结果:**
```
new|7679
update|1
```

随着系统运行，`update`记录会逐渐增加。

## 🛠️ 故障排查

### 问题1: 提示"无法获取commit SHA"

**原因:**
- 网络连接问题
- GitHub API限流
- 仓库不存在或私有

**解决方案:**
```bash
# 检查网络连接
curl -I https://api.github.com

# 检查API限流状态
curl https://api.github.com/rate_limit
```

### 问题2: 所有仓库都被跳过

**原因:** SHA已填充且无更新

**验证:**
```bash
# 查看某个仓库的SHA
sqlite3 vulns.db "
SELECT url, latest_commit_sha, updated_at
FROM repositories
WHERE github_id = 948271266
"
```

### 问题3: 迁移脚本执行很慢

**原因:** 正常现象，需要调用7680次API

**优化建议:**
- 迁移脚本每10个请求暂停1秒（避免限流）
- 可在后台运行: `nohup python scripts/migrate_commit_sha.py > migration.log 2>&1 &`
- 查看进度: `tail -f migration.log`

## 📚 相关文档

- **详细优化报告:** [OPTIMIZATION_SUMMARY.md](OPTIMIZATION_SUMMARY.md)
- **测试脚本:** [test_update_logic.py](test_update_logic.py)
- **迁移脚本:** [scripts/migrate_commit_sha.py](scripts/migrate_commit_sha.py)

## 🔗 技术参考

- [GitHub API - List commits](https://docs.github.com/en/rest/commits/commits#list-commits)
- [Git SHA-1 规范](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)

## ❓ 常见问题

**Q: 更新检测会影响性能吗？**
A: 不会。API调用非常轻量（只获取1个commit），通常在100-200ms内完成。相比克隆仓库（数秒到数十秒），性能反而提升了。

**Q: 如果GitHub API限流怎么办？**
A: 当前使用未认证API（60次/小时限制）。如果触发限流，可以：
1. 添加GitHub Token（提升到5000次/小时）
2. 暂时关闭更新检测（`ENABLE_UPDATE_CHECK=False`）

**Q: 更新模式和新增模式有什么区别？**
A:
- **新增模式**（action_log='new'）：插入新记录
- **更新模式**（action_log='update'）：更新现有记录，避免同一仓库产生多条记录

**Q: 为什么要用commit SHA而不是pushed_at时间？**
A:
- `pushed_at` 不可靠，可能被各种push事件触发（分支、tag等）
- `commit SHA` 精确唯一，只有代码变化才会改变

---

**维护日期:** 2025-11-27
**版本:** 1.0

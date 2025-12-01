# 快速测试指南

## 🚀 5分钟快速测试

### 最简单的方式（一键测试）

```bash
./test_local.sh
```

这个脚本会自动完成所有准备工作并运行测试。

---

## 📝 测试文件说明

| 文件 | 用途 |
|------|------|
| `test_local.sh` | 一键测试脚本（推荐） |
| `test_main.py` | 测试主程序（处理前3个CVE） |
| `.env.test` | 测试环境配置模板 |
| `TEST_GUIDE.md` | 详细测试文档 |

---

## ⚙️ 配置选项

### 选项1：最小测试（无需API）

**适合：** 快速验证基础功能

在 `config.py` 中设置：
```python
ENABLE_GPT = False
ENABLE_SEARCH = False
ENABLE_NOTIFY = False
```

运行：
```bash
./test_local.sh
```

---

### 选项2：完整测试（需要GPT API）

**适合：** 验证所有新功能

1. 复制配置文件：
```bash
cp .env.test .env
```

2. 编辑 `.env`，填写你的 API 密钥：
```bash
GPT_SERVER_URL=https://your-gpt-server/v1/chat/completions
GPT_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

3. 在 `config.py` 中启用 GPT：
```python
ENABLE_GPT = True
```

4. 运行测试：
```bash
./test_local.sh
```

---

## 📊 测试验证

测试完成后，检查：

1. **控制台输出**
   - 成功率 ≥ 90%
   - 无严重错误

2. **监控摘要**
   ```
   成功率: 100.0%
   临时文件清理率: 100.0%
   ```

3. **生成的文件**
   - `test_monitor_result.json` - 监控数据
   - `data/{YEAR}/{CVE-ID}.md` - 分析报告

4. **临时文件清理**
   ```bash
   ls /tmp | grep vulnwatchdog
   # 应该没有输出（表示清理成功）
   ```

---

## 🎯 测试重点

本次测试主要验证以下**新增功能**：

- ✅ **监控模块**：运行统计、错误追踪
- ✅ **临时文件清理**：自动清理克隆目录
- ✅ **GPT解析鲁棒性**：支持多种JSON格式
- ✅ **更新检测**：基于Commit SHA的精确判断

---

## 🐛 遇到问题？

查看详细文档：
```bash
cat TEST_GUIDE.md
```

或查看错误详情：
```bash
cat test_monitor_result.json | jq '.errors'
```

---

## ✅ 测试通过后

如果本地测试通过，可以：

1. 运行完整版本：
   ```bash
   python main.py
   ```

2. 推送到 GitHub 进行 Actions 测试：
   ```bash
   git add .
   git commit -m "test: 验证新功能稳定性"
   git push
   ```

---

**祝测试顺利！** 🎉

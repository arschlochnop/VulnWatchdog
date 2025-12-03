# GitHub Token 配置指南

## 概述

VulnWatchdog 使用 GitHub API 获取仓库信息和提交历史。为避免触发 API 速率限制（Rate Limit），推荐配置 GitHub Token。

## 速率限制对比

| 配置方式 | API 限额 | 适用场景 |
|---------|---------|---------|
| 未配置 Token | 60次/小时 | ❌ 测试（容易触发限制） |
| GitHub Actions Token | 1000次/小时 | ✅ CI/CD 自动化 |
| Personal Access Token | 5000次/小时 | ✅ 本地开发 + 生产环境 |

---

## 配置方式

### 优先级规则

系统按以下优先级读取 Token：

```
1. GH_TOKEN (用户手工配置) - 5000次/小时
   ↓ 如果未设置
2. GITHUB_TOKEN (GitHub Actions 自动提供) - 1000次/小时
   ↓ 如果未设置
3. 未认证模式 - 60次/小时
```

---

## 方案 1: GitHub Actions 自动 Token（推荐 CI/CD）

**适用场景**: GitHub Actions 工作流

**优点**:
- ✅ 无需手动配置
- ✅ 自动刷新
- ✅ 1000次/小时限额

**配置**:

工作流已自动配置，无需额外操作：

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # 自动��供
```

---

## 方案 2: Personal Access Token（推荐本地开发）

**适用场景**: 本地开发、高频率使用

**优点**:
- ✅ 5000次/小时限额（最高）
- ✅ 可控制权限��围
- ✅ 本地和 CI 通用

### 步骤 1: 生成 Token

1. 访问 GitHub Token 设置页面:
   ```
   https://github.com/settings/tokens
   ```

2. 点击 **"Generate new token (classic)"**

3. 配置 Token:
   - **Note**: `VulnWatchdog API Access`
   - **Expiration**: 选择有效期（建议 90天 或 无限期）
   - **Scopes**: 勾选 `public_repo` （读取公共仓库）

4. 点击 **"Generate token"**

5. **复制生成的 Token** (只显示一次！)
   ```
   ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

### 步骤 2: 本地配置

在项目根目录的 `.env` 文件中添加：

```bash
# GitHub Personal Access Token
GH_TOKEN=ghp_your_token_here
```

### 步骤 3: GitHub Actions 配置（可选）

如果希望在 GitHub Actions 中也使用更高限额：

1. 访问仓库设置:
   ```
   https://github.com/your-username/VulnWatchdog/settings/secrets/actions
   ```

2. 点击 **"New repository secret"**

3. 配置 Secret:
   - **Name**: `GH_TOKEN`
   - **Secret**: 粘贴你的 Personal Access Token
   - 点击 **"Add secret"**

---

## 验证配置

### 本地测试

```bash
# 运行程序并观察日志
python main.py

# 应该看到类似输出:
# ✓ 使用 GitHub Token: ghp_****...
# ✓ API 限额: 5000/小时
```

### GitHub Actions 验证

查看 Actions 运行日志，应该不再出现：

```
❌ 403 Client Error: rate limit exceeded
```

---

## 常见问题

### Q1: 为什么不能使用 `GITHUB_TOKEN` 作为 Secret 名称？

**A**: `GITHUB_TOKEN` 是 GitHub Actions 的保留关键字，无法作为自定义 Secret。因此使用 `GH_TOKEN` 作为用户配置的变量名。

### Q2: GH_TOKEN 和 GITHUB_TOKEN 有什么区别？

| 项目 | GH_TOKEN | GITHUB_TOKEN |
|-----|----------|--------------|
| 来源 | 用户手动创建 | GitHub Actions 自动提供 |
| 限额 | 5000次/小时 | 1000次/小时 |
| 配置 | 需要手动配置 | 自动可用 |
| 权限 | 可自定义 | 受工作流限制 |
| 使用场景 | 本地 + CI | 仅 CI |

### Q3: Token 会被提交到 Git 吗？

**A**: 不会。`.env` 文件已在 `.gitignore` 中排除，不会被提交到仓库。

### Q4: 忘记保存 Token 怎么办？

**A**: Token 只在生成时显示一次。如果忘记保存，需要删除旧 Token 并重新生成。

### Q5: 如何查看当前 API 限额使用情况？

**A**: 运行以下命令：

```bash
# 查看当前速率限制
curl -H "Authorization: token YOUR_TOKEN" \
  https://api.github.com/rate_limit
```

输出示例：
```json
{
  "rate": {
    "limit": 5000,
    "remaining": 4950,
    "reset": 1234567890
  }
}
```

---

## 安全建议

1. **最小权限原则**: 只赋予 `public_repo` 权限
2. **定期轮换**: 建议每 90 天更新一次 Token
3. **泄露处理**: 如 Token 泄露，立即到 GitHub 撤销该 Token
4. **不要硬编码**: 永远不要将 Token 写在代码中

---

## 配置示例

### 本地 `.env` 文件

```bash
# VulnWatchdog 环境变量配置

# GitHub Token (推荐配置)
GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 其他配置...
GPT_API_KEY=sk-your-api-key
WEBHOOK_URL=https://your-webhook-url
```

### GitHub Actions Secrets

```
Repository Settings > Secrets and variables > Actions

Secrets:
✓ GH_TOKEN (optional, 5000/hour)
✓ GPT_API_KEY
✓ WEBHOOK_URL
✓ ...
```

---

## 技术实现

配置读取逻辑 (`config.py`):

```python
# 优先级: GH_TOKEN > GITHUB_TOKEN > None
'GITHUB_TOKEN': os.environ.get('GH_TOKEN') or \
                os.environ.get('GITHUB_TOKEN') or \
                GITHUB_TOKEN
```

这样确保：
1. 如果设置了 `GH_TOKEN`，使用用户配置（5000/小时）
2. 否则使用 `GITHUB_TOKEN`（GitHub Actions 自动提供，1000/小时）
3. 都没有则使用未认证模式（60/小时）

---

## 相关链接

- [GitHub Token 文档](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
- [GitHub API 速率限制](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

---

*最后更新: 2025-12-03*

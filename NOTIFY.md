# 消息通知模板说明

## 模板变量

消息模板支持以下变量替换(展示部分,更多请参考下面数据结构内容):


### CVE 信息
- `{cve.title}` - CVE标题
- `{cve.description}` - CVE描述
- `{cve.published}` - CVE发布时间
- `{cve.lastModified}` - CVE最后修改时间
- `{cve.severity}` - CVE严重性
- `{cve.cvssMetricV31}` - CVECVSS评分信息
- `{cve.references}` - CVE参考链接

### 仓库信息
- `{repo.name}` - 仓库名称
- `{repo.description}` - 仓库描述
- `{repo.html_url}` - 仓库URL
- `{repo.pushed_at}` - 仓库最后推送时间
- `{repo.action_log}` - 动作日志(new/update)

### GPT分析信息
- `{gpt.name}` - 漏洞名称
- `{gpt.type}` - 漏洞类型
- `{gpt.app}` - 受影响应用
- `{gpt.risk}` - 风险等级和影响
- `{gpt.version}` - 受影响版本
- `{gpt.condition}` - 利用条件
- `{gpt.poc_available}` - 是否有可用POC
- `{gpt.poison}` - 投毒风险百分比
- `{gpt.markdown}` - Markdown格式的详细分析

数据结构
```json
   {
        'cve': {
            'title': '...',                  # CVE标题
            'description': {                 # 描述信息
                'value': '...'
            },
            # 其他CVE信息字段,可能包括:
            'published': '...',              # 发布日期
            'lastModified': '...',           # 最后修改日期
            'severity': '...',               # 严重性
            'cvssMetricV31': [...],          # CVSS评分信息
            'references': [...],             # 参考链接
            # ...其他字段参考：https://cve.circl.lu/api/cve/CVE-2024-10629
        },
        
        'repo': {
            'id': 123456789,                 # GitHub仓库ID
            'name': '...',                   # 仓库名称
            'full_name': 'owner/repo',       # 完整仓库名
            'html_url': 'https://github.com/owner/repo',  # 仓库URL
            'description': '...',            # 仓库描述
            'pushed_at': '2023-01-01T00:00:00Z',  # 最后推送时间
            # ...其他字段参考: https://api.github.com/repos/arschlochnop/VulnWatchdog
        },
        
        'gpt': {
            # GPT分析结果,完整结构
            'name': 'CVE-2023-XXXXX-应用名称-漏洞类型',  # 漏洞名称
            'type': '命令注入/SQL注入/XSS/...',         # 漏洞类型
            'app': '受影响的应用名称',                  # 受影响应用
            'risk': '高危，可能导致远程代码执行...',     # 风险等级和影响
            'version': '<= X.Y.Z',                    # 受影响版本
            'condition': '需要认证/无需认证...',         # 利用条件
            'poc_available': '是/否',                  # 是否有可用POC
            'poison': '90%',                          # 投毒风险百分比
            'markdown': '## 漏洞分析\n详细的漏洞分析内容...',  # Markdown格式的详细分析
            
            # 以下添加的额外字段
            'cve_id': 'CVE-2023-XXXXX',               # CVE编号
            'repo_name': 'owner/repo',                # 仓库全名
            'repo_url': 'https://github.com/owner/repo',  # 仓库URL
            'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX',  # CVE详情页URL
            'action_log': 'new/update'                # 操作日志(新发现或更新)
            'git_url': 'https://github.com/xxxx/xxxx',  # 自身项目地址，使用github action部署才有
        }
    }
```


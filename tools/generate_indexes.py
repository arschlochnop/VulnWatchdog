#!/usr/bin/env python3
"""
生成CVE数据索引和README文件
- data/README.md: 主索引页面，包含统计信息
- data/{year}/README.md: 各年份的CVE列表
- data/by-cve/{CVE-ID}.md: 符号链接到实际文件
"""

import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
BY_CVE_DIR = DATA_DIR / "by-cve"


def extract_cve_id(filename):
    """从文件名中提取CVE ID"""
    match = re.match(r'(CVE-\d{4}-\d+)', filename)
    return match.group(1) if match else None


def extract_year_from_cve(cve_id):
    """从CVE ID提取年份"""
    match = re.match(r'CVE-(\d{4})-', cve_id)
    return match.group(1) if match else None


def parse_cve_file(filepath):
    """解析CVE文件，提取元数据"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # 提取标题（第一行）
        lines = content.split('\n')
        title = lines[0].strip('#').strip() if lines else ''

        # 提取关键信息
        severity = 'N/A'
        description = ''

        for line in lines:
            if line.startswith('- **严重程度**:') or line.startswith('- **Severity**:'):
                severity = line.split(':', 1)[1].strip()
            elif line.startswith('## 漏洞描述') or line.startswith('## Description'):
                idx = lines.index(line)
                if idx + 1 < len(lines):
                    description = lines[idx + 1].strip()
                    break

        return {
            'title': title,
            'severity': severity,
            'description': description[:200]  # 限制长度
        }
    except Exception as e:
        print(f"解析文件失败 {filepath}: {e}")
        return {'title': '', 'severity': 'N/A', 'description': ''}


def collect_cve_data():
    """收集所有CVE数据"""
    cve_by_year = defaultdict(list)
    cve_by_id = {}
    total_repos = 0

    # 遍历年份目录
    for year_dir in sorted(DATA_DIR.iterdir()):
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue

        year = year_dir.name

        # 遍历该年份的CVE文件
        for cve_file in sorted(year_dir.glob('CVE-*.md')):
            cve_id = extract_cve_id(cve_file.name)
            if not cve_id:
                continue

            # 解析文件
            metadata = parse_cve_file(cve_file)

            # 统计POC仓库数（通过文件名中的仓库链接）
            repo_count = len(re.findall(r'github\.com/[\w-]+/[\w-]+', cve_file.name))
            total_repos += repo_count

            cve_info = {
                'id': cve_id,
                'year': year,
                'filename': cve_file.name,
                'filepath': cve_file,
                'repo_count': repo_count,
                **metadata
            }

            cve_by_year[year].append(cve_info)

            # by-cve索引
            if cve_id not in cve_by_id:
                cve_by_id[cve_id] = []
            cve_by_id[cve_id].append(cve_info)

    return cve_by_year, cve_by_id, total_repos


def generate_year_readme(year, cves, output_dir):
    """生成年份README"""
    output_file = output_dir / f"{year}/README.md"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# {year}年 CVE漏洞列表

> 📊 共收录 **{len(cves)}** 个CVE漏洞

---

## 📋 漏洞列表

| CVE编号 | 标题 | 严重程度 | POC仓库数 |
|---------|------|----------|-----------|
"""

    for cve in sorted(cves, key=lambda x: x['id']):
        title = cve['title'][:60] + '...' if len(cve['title']) > 60 else cve['title']
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(cve['severity'].upper().split()[0] if cve['severity'] != 'N/A' else '', '⚪')

        content += f"| [{cve['id']}]({cve['filename']}) | {title} | {severity_emoji} {cve['severity']} | {cve['repo_count']} |\n"

    content += f"""
---

## 📚 相关链接

- [返回主页](../README.md)
- [按CVE查找](../by-cve/)
- [其他年份CVE](../README.md#年度分布)

---

*最后更新: {datetime.now().strftime('%Y-%m-%d')}*
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✓ 生成年份索引: {output_file}")


def generate_by_cve_index(cve_by_id):
    """生成by-cve目录的索引文件"""
    BY_CVE_DIR.mkdir(parents=True, exist_ok=True)

    for cve_id, cve_list in cve_by_id.items():
        # 如果一个CVE有多个POC，合并到一个文件
        output_file = BY_CVE_DIR / f"{cve_id}.md"

        if len(cve_list) == 1:
            # 单个POC，创建符号链接或复制内容
            src_file = cve_list[0]['filepath']
            try:
                with open(src_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                print(f"  警告: 创建索引失败 {cve_id}: {e}")
        else:
            # 多个POC，合并到一个文件
            content = f"# {cve_id}\n\n"
            content += f"> 📦 该CVE有 **{len(cve_list)}** 个相关POC仓库\n\n---\n\n"

            for idx, cve in enumerate(cve_list, 1):
                content += f"## POC #{idx}\n\n"
                content += f"**来源**: [{cve['filename']}](../{cve['year']}/{cve['filename']})\n\n"

                try:
                    with open(cve['filepath'], 'r', encoding='utf-8') as f:
                        poc_content = f.read()
                    content += poc_content + "\n\n---\n\n"
                except Exception as e:
                    content += f"_读取失败: {e}_\n\n---\n\n"

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)


def generate_main_readme(cve_by_year, total_cves, total_repos):
    """生成主README"""
    output_file = DATA_DIR / "README.md"

    # 计算统计信息
    years_sorted = sorted(cve_by_year.keys(), reverse=True)

    content = f"""# VulnWatchdog - 漏洞情报库

> 🤖 自动化CVE漏洞监控与分析系统
> 📅 最后更新: {datetime.now().strftime('%Y-%m-%d')}
> 📊 已收录: **{total_cves}** 个CVE | **{total_repos}** 个POC仓库

---

## 🚀 快速开始

### 浏览方式
- 📅 **按年份浏览** - 查看特定年份的CVE漏洞
"""

    for year in years_sorted[:5]:  # 显示最近5年
        count = len(cve_by_year[year])
        content += f"  - [{year}年]({year}/README.md) ({count} 个)\n"

    content += f"""- 🔍 **按CVE编号查找** - 直接访问 `by-cve/CVE-XXXX-XXXXX.md`
- 📰 **订阅更新** - 见下方订阅方式

### 订阅方式
- 🔔 **GitHub Watch** - 点击右上角 ⭐ Star 和 👁️ Watch 接收更新通知
- 📡 **RSS订阅** - 添加到RSS阅读器:
  ```
  https://github.com/VulnWatchdog/VulnWatchdog/commits.atom
  ```
- 💬 **飞书通知** - Fork后配置Webhook接收实时推送

---

## 📊 数据统计

### 年度分布

| 年份 | 漏洞数量 | 占比 |
|------|---------|------|
"""

    for year in years_sorted:
        count = len(cve_by_year[year])
        percentage = (count / total_cves * 100) if total_cves > 0 else 0
        content += f"| [{year}]({year}/README.md) | {count} | {percentage:.1f}% |\n"

    content += f"""
### 热门CVE Top 10

"""

    # 找出POC数量最多的CVE
    all_cves = []
    for year_cves in cve_by_year.values():
        all_cves.extend(year_cves)

    top_cves = sorted(all_cves, key=lambda x: x['repo_count'], reverse=True)[:10]

    content += "| CVE编号 | POC仓库数 | 年份 |\n"
    content += "|---------|-----------|------|\n"

    for cve in top_cves:
        content += f"| [{cve['id']}](by-cve/{cve['id']}.md) | {cve['repo_count']} | {cve['year']} |\n"

    content += f"""
---

## 🛠️ 使用说明

### 搜索CVE
```bash
# 按CVE编号查找
cat data/by-cve/CVE-2024-1234.md

# 按年份查找
ls data/2024/

# 搜索关键词
grep -r "RCE" data/2024/
```

### API使用
```python
# 通过GitHub API获取最新CVE
import requests

url = "https://api.github.com/repos/VulnWatchdog/VulnWatchdog/commits"
response = requests.get(url)
latest_commit = response.json()[0]
print(f"最新更新: {{latest_commit['commit']['message']}}")
```

---

## 📖 相关文档

- [项目主页](../README.md)
- [通知配置](../NOTIFY.md)
- [贡献指南](../README.md#贡献)

---

*本项目由 VulnWatchdog 自动维护 | [GitHub](https://github.com/VulnWatchdog/VulnWatchdog)*
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✓ 生成主索引: {output_file}")


def main():
    """主函数"""
    print("🚀 开始生成CVE索引...")

    # 收集数据
    print("📊 收集CVE数据...")
    cve_by_year, cve_by_id, total_repos = collect_cve_data()
    total_cves = sum(len(cves) for cves in cve_by_year.values())

    print(f"  - 收集到 {total_cves} 个CVE")
    print(f"  - 跨越 {len(cve_by_year)} 个年份")
    print(f"  - 共 {total_repos} 个POC仓库")

    # 生成年份README
    print("\n📝 生成年份索引...")
    for year, cves in cve_by_year.items():
        generate_year_readme(year, cves, DATA_DIR)

    # 生成by-cve索引
    print("\n🔗 生成CVE索引...")
    generate_by_cve_index(cve_by_id)
    print(f"✓ 生成 {len(cve_by_id)} 个CVE索引文件")

    # 生成主README
    print("\n📋 生成主索引...")
    generate_main_readme(cve_by_year, total_cves, total_repos)

    print("\n✅ 索引生成完成!")


if __name__ == "__main__":
    main()

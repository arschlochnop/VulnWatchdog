from datetime import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import traceback
import requests
from config import get_config
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from libs.files2prompt import process_path

logger = logging.getLogger(__name__)

def get_latest_commit_sha(repo_url: str) -> Optional[str]:
    """
    通过GitHub API获取仓库最新commit SHA (无需clone)

    参数:
        repo_url: GitHub仓库URL (https://github.com/owner/repo)

    返回:
        最新commit的SHA值,失败返回None
    """
    try:
        # 从URL提取 owner/repo
        match = re.match(r'https://github\.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            logger.error(f"无效的GitHub URL: {repo_url}")
            return None

        owner, repo = match.groups()
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"

        # 构建请求头（如果配置了Token则添加认证）
        headers = {}
        github_token = get_config('GITHUB_TOKEN')
        if github_token:
            headers['Authorization'] = f'token {github_token}'
            logger.debug("使用GitHub Token认证")

        # 调用GitHub API (只获取最新1个commit)
        resp = requests.get(
            api_url,
            params={'per_page': 1},
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()

        commits = resp.json()
        if commits and len(commits) > 0:
            sha = commits[0]['sha']
            logger.debug(f"获取到最新commit SHA: {sha[:8]}... (仓库: {owner}/{repo})")
            return sha
        else:
            logger.warning(f"仓库无commit记录: {repo_url}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"请求GitHub API失败: {e} (仓库: {repo_url})")
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"解析API响应失败: {e} (仓库: {repo_url})")
    except Exception as e:
        logger.error(f"获取commit SHA异常: {e} (仓库: {repo_url})")

    return None

def search_github(query: str) -> Tuple[set, List[Dict]]:
    """
    搜索GitHub仓库中的CVE信息

    参数:
        query: 搜索关键词

    返回:
        (cve_id集合, 仓库信息列表)
    """
    current_year = datetime.now().year
    re_cve = re.compile(r'(?i)CVE-(\d{3,5})-\d{3,5}')

    try:
        # 构建请求头（如果配置了Token则添加认证）
        headers = {}
        github_token = get_config('GITHUB_TOKEN')
        if github_token:
            headers['Authorization'] = f'token {github_token}'
            logger.debug("使用GitHub Token认证（搜索API）")

        url = f"https://api.github.com/search/repositories?q={query}&sort=updated"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"访问GitHub API失败: {e}")
        return set(), []

    cve_list = set()
    repo_list = []
    
    items = resp.json().get('items', [])
    logger.info(f"GitHub搜索到 {len(items)} 个仓库")
    
    for item in items:
        try:

            name = item.get('name', '') if item.get('name', '') else ''
            desc = item.get('description', '') if item.get('description', '') else ''
            cve_match = re_cve.search(name + desc)
            if not cve_match:
                continue
                
            cve_id = cve_match.group(0).upper()
            cve_year = int(cve_match.group(1))
            
            if cve_year > current_year:
                logger.warning(f"CVE年份异常: {cve_id}")
                continue
                
            cve_list.add(cve_id)
            repo_list.append({'cve_id': cve_id, 'repo': item})
            logger.debug(f"找到CVE: {cve_id}, 仓库: {item['html_url']}")
            
        except Exception as e:
            logger.error(f"处理仓库信息异常: {e}")
            traceback.print_exc()
            continue
            
    logger.info(f"共找到 {len(cve_list)} 个CVE, {len(repo_list)} 个相关仓库")
    return cve_list, repo_list

def get_cve_info(cve_id: str) -> Dict:
    """
    从NVD获取CVE详细信息
    
    参数:
        cve_id: CVE编号
        
    返回:
        CVE信息字典
    """
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        
        data = resp.json()
        if not data:
            logger.error(f"漏洞库暂未收录此漏洞 {cve_id}")
            return {}
        logger.info(f"获取CVE信息成功: {cve_id}")
        return data
        
    except requests.exceptions.RequestException as e:
        logger.error(f"请求CVE API失败: {e}")
    except Exception as e:
        logger.error(f"获取CVE信息异常: {e}")
        
    return {}

class SearchError(Exception):
    """搜索相关错误的自定义异常"""
    pass

def search_searxng(query: str, num_results: int = 5) -> List[Dict]:
    """
    使用Searx执行搜索
    
    参数:
        query: 搜索关键词
        num_results: 返回结果数量
        
    返回:
        搜索结果列表
        
    异常:
        SearchError: 搜索失败
    """
    url = get_config('SEARXNG_URL')

    # 检查URL是否配置
    if not url or url == 'None':
        logger.warning(f"SEARXNG_URL未配置，跳过搜索")
        return []

    params = {
        "q": query,
        "format": "json",
        "pageno": 1,
        "engines": "google",
        "max_results": num_results
    }

    try:
        response = requests.get(url, params=params, verify=True, timeout=10)
        response.raise_for_status()
        
        results = response.json().get("results", [])
        logger.info(f"搜索 '{query}' 获得 {len(results)} 个结果")
        return results
        
    except requests.exceptions.RequestException as e:
        logger.error(f"搜索请求失败: {e}")
        return []  # 搜索失败时返回空列表，不中断流程
    except json.JSONDecodeError as e:
        logger.error(f"解析搜索结果失败: {e}")
        return []  # 解析失败时返回空列表，不中断流程

def __extract_json_from_markdown(content: str) -> Optional[str]:
    """
    从markdown格式的GPT响应中提取JSON内容

    支持多种格式:
    - ```json\n{...}\n```
    - ```JSON\n{...}\n```
    - ```\n{...}\n```
    - 直接JSON: {...}

    参数:
        content: GPT返回的原始内容

    返回:
        提取的JSON字符串,失败返回None
    """
    # 尝试1: 使用正则提取markdown代码块
    patterns = [
        r'```json\s*\n?(.*?)\n?```',  # ```json ... ```
        r'```JSON\s*\n?(.*?)\n?```',  # ```JSON ... ```
        r'```\s*\n?(.*?)\n?```',      # ``` ... ```
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            logger.debug(f"通过正则提取JSON (模式: {pattern})")
            return match.group(1).strip()

    # 尝试2: 查找第一个 { 到最后一个 } 之间的内容
    first_brace = content.find('{')
    last_brace = content.rfind('}')

    if first_brace != -1 and last_brace != -1 and first_brace < last_brace:
        extracted = content[first_brace:last_brace + 1]
        logger.debug("通过大括号匹配提取JSON")
        return extracted

    # 尝试3: 直接返回原内容（可能本身就是JSON）
    logger.debug("无法提取，尝试直接解析原内容")
    return content.strip()


def ask_gpt(prompt: str) -> Optional[Dict]:
    """
    调用OpenAI API进行分析

    参数:
        prompt: 提示文本

    返回:
        API响应解析后的字典,失败返回None
    """
    headers = {
        "Authorization": f"Bearer {get_config('GPT_API_KEY')}",
        "Content-Type": "application/json"
    }

    data = {
        "model": get_config('GPT_MODEL'),
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post(
            get_config('GPT_SERVER_URL'),
            headers=headers,
            json=data,
            verify=True,
            timeout=60
        )
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        logger.debug(f"GPT返回内容长度: {len(content)}")

        if not content:
            logger.warning(f"GPT返回内容为空 prompt长度: {len(prompt)}")
            return None

        # 渐进式解析策略
        json_candidates = []

        # 策略1: 提取JSON（支持多种格式）
        extracted = __extract_json_from_markdown(content)
        if extracted:
            json_candidates.append(extracted)

        # 策略2: 原始内容（删除首尾空白）
        json_candidates.append(content.strip())

        # 策略3: 移除所有换行后的内容（兼容旧逻辑）
        json_candidates.append(content.replace('\n', ''))

        # 尝试解析
        for idx, candidate in enumerate(json_candidates, 1):
            try:
                result = json.loads(candidate)
                logger.info(f"JSON解析成功 (策略{idx})")
                return result
            except json.JSONDecodeError as e:
                logger.debug(f"策略{idx}解析失败: {e}")
                continue

        # 所有策略都失败
        logger.error(f"所有解析策略均失败 prompt长度: {len(prompt)}")
        logger.error(f"原始内容: {content[:500]}...")  # 只记录前500字符
        return None

    except requests.exceptions.RequestException as e:
        # 特殊处理429限流错误
        if hasattr(e, 'response') and e.response is not None and e.response.status_code == 429:
            logger.warning(f"GPT API请求限流 (429)，跳过此POC - prompt长度: {len(prompt)}")
        else:
            logger.error(f"请求GPT API失败: {e} prompt长度: {len(prompt)}")
            traceback.print_exc()
    except (KeyError, IndexError) as e:
        logger.error(f"处理GPT响应异常: {e} prompt长度: {len(prompt)}")
    except Exception as e:
        logger.error(f"未知异常: {e} prompt长度: {len(prompt)}")
        traceback.print_exc()

    return None

def __clone_repo(url: str) -> Optional[str]:
    """
    克隆Git仓库（临时目录，使用后需清理）

    参数:
        url: 仓库地址

    返回:
        克隆目录路径,失败返回None

    注意:
        调用者负责清理返回的临时目录
    """
    unique_id = hashlib.md5(url.encode()).hexdigest()
    clone_path = Path('/tmp') / f'vulnwatchdog_{unique_id}'

    # 如果目录已存在，先删除（确保是最新的）
    if clone_path.exists():
        logger.debug(f"删除已存在的旧克隆: {clone_path}")
        try:
            shutil.rmtree(clone_path)
        except Exception as e:
            logger.warning(f"删除旧克隆失败: {e}")

    try:
        logger.info(f"克隆仓库: {url}")
        subprocess.run(
            ['git', 'clone', '--depth', '1', url, str(clone_path)],  # 浅克隆
            check=True,
            capture_output=True,
            timeout=60
        )

        if clone_path.exists():
            logger.debug(f"克隆成功: {clone_path}")
            return str(clone_path)
        else:
            logger.error("克隆成功但目录不存在")
            return None

    except subprocess.TimeoutExpired:
        logger.error(f"克隆仓库超时: {url}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"克隆仓库失败: {e.stderr.decode()}")
        return None

def get_github_poc(github_link: str) -> str:
    """
    获取GitHub仓库中的POC代码（智能筛选）

    参数:
        github_link: GitHub仓库链接

    返回:
        POC代码内容
    """
    clone_path = None
    try:
        clone_path = __clone_repo(github_link)
        if not clone_path:
            logger.error("克隆仓库失败")
            return ''

        # 智能忽略模式：跳过常见的无关目录和文件
        ignore_patterns = [
            # 依赖目录
            'node_modules/*',
            'vendor/*',
            '.venv/*',
            'venv/*',
            '__pycache__/*',
            '*.egg-info/*',

            # 构建产物
            'dist/*',
            'build/*',
            'target/*',
            '*.min.js',
            '*.min.css',

            # 文档和媒体
            'docs/*',
            'doc/*',
            'documentation/*',
            '*.png',
            '*.jpg',
            '*.jpeg',
            '*.gif',
            '*.svg',
            '*.ico',
            '*.pdf',

            # 配置和元数据
            '.git/*',
            '.github/*',
            '.vscode/*',
            '.idea/*',
            '*.lock',
            'package-lock.json',
            'yarn.lock',
            'Cargo.lock',

            # 其他
            '*.log',
            '*.tmp',
            '*.bak',
            '*.swp',
            '*.DS_Store',
        ]

        outputs = process_path(
            path=clone_path,
            extensions=None,  # 不限制扩展名（保留README等）
            include_hidden=False,
            ignore_files_only=False,
            ignore_gitignore=True,  # 启用gitignore（尊重项目配置）
            gitignore_rules=[],
            ignore_patterns=ignore_patterns,  # 使用智能忽略模式
            claude_xml=False,
            markdown=False,
            line_numbers=False
        )

        logger.info(f"成功提取POC代码: {len(outputs)} 行 (已过滤无关文件)")
        return '\n'.join(outputs)

    except Exception as e:
        logger.error(f"获取POC代码异常: {e}")
        return ''

    finally:
        # 无论成功失败，都清理临时目录
        if clone_path and Path(clone_path).exists():
            try:
                shutil.rmtree(clone_path)
                logger.debug(f"清理临时目录: {clone_path}")
            except Exception as e:
                logger.warning(f"清理临时目录失败: {e}")


def get_template():
    with open('template/report.md', 'r', encoding='utf-8') as file:
        return file.read()

def write_to_markdown(data: Dict, filename: str):
    """
    将内容写入markdown文件
    
    参数:
        data: 内容
        filename: 文件名
    """
    # 确保目录存在
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    template = get_template()
    content = template.format(**data)
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)
from datetime import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import traceback
import requests
from config import get_config
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from libs.files2prompt import process_path

logger = logging.getLogger(__name__)

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
        url = f"https://api.github.com/search/repositories?q={query}&sort=updated"
        resp = requests.get(url, timeout=10)
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
        raise SearchError(f"搜索请求失败: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"解析搜索结果失败: {e}")
        raise SearchError(f"无效的搜索响应: {e}")

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
        content = re.sub(r'\s*\n\s*', ' ', content)
        logger.debug(f"GPT返回内容: {content}")
        if not content:
            logger.warning(f"GPT返回内容为空 prompt长度: {len(prompt)}")
            return None
            
        try:
            if content.startswith('```json'):
                content = content[7:-3].strip()
            return json.loads(content.replace('\n', ''))
            
        except json.JSONDecodeError as e:
            logger.error(f"解析GPT响应JSON失败: {e} prompt长度: {len(prompt)}")
            logger.error(content)
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"请求GPT API失败: {e} prompt长度: {len(prompt)}")
        traceback.print_exc()
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"处理GPT响应异常: {e} prompt长度: {len(prompt)}")
        
    return None

def __clone_repo(url: str) -> Optional[str]:
    """
    克隆Git仓库
    
    参数:
        url: 仓库地址
        
    返回:
        克隆目录路径,失败返回None
    """
    unique_id = hashlib.md5(url.encode()).hexdigest()
    clone_path = Path('/tmp') / unique_id
    
    if clone_path.exists():
        logger.debug(f"使用已存在的仓库克隆: {clone_path}")
        return str(clone_path)
        
    try:
        logger.info(f"克隆仓库: {url}")
        subprocess.run(
            ['git', 'clone', url, str(clone_path)],
            check=True,
            capture_output=True
        )
        
        if clone_path.exists():
            return str(clone_path)
        else:
            logger.error("克隆成功但目录不存在")
            return None
            
    except subprocess.CalledProcessError as e:
        logger.error(f"克隆仓库失败: {e.stderr.decode()}")
        return None

def get_github_poc(github_link: str) -> str:
    """
    获取GitHub仓库中的POC代码
    
    参数:
        github_link: GitHub仓库链接
        
    返回:
        POC代码内容
    """
    try:
        clone_path = __clone_repo(github_link)
        if not clone_path:
            logger.error("克隆仓库失败")
            return ''
            
        outputs = process_path(
            path=clone_path,
            extensions=None,
            include_hidden=False,
            ignore_files_only=False,
            ignore_gitignore=False,
            gitignore_rules=[],
            ignore_patterns=[],
            claude_xml=False,
            markdown=False,
            line_numbers=False
        )
        
        logger.info(f"成功提取POC代码: {len(outputs)} 行")
        return '\n'.join(outputs)
        
    except Exception as e:
        logger.error(f"获取POC代码异常: {e}")
        return ''


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
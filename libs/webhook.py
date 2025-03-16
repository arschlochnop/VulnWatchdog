import json
import os
import requests
from config import get_config
import logging

logger = logging.getLogger(__name__)


def parse_webhook_data(webhook_data,data):
    """
    解析webhook数据并替换变量
    
    Args:
        webhook_data: webhook消息模板,支持字符串或字典格式
                     模板中可使用${key}形式的变量,key为data中的字段路径
                     例如:
                     - ${cve.title} - CVE标题
                     - ${repo.html_url} - 仓库URL
                     - ${gpt.risk} - GPT分析的风险等级
                     
        data: 包含CVE、仓库、GPT分析结果的字典数据
    
    Returns:
        解析后的webhook数据:
        
    示例:
        webhook_data = {
            "text": "发现新漏洞 ${cve.title}",
            "desp": "风险等级: ${gpt.risk}\n详情: ${repo.html_url}"
        }
        
        data = {
            "cve": {"title": "RCE漏洞"},
            "gpt": {"risk": "高危"},
            "repo": {"html_url": "https://github.com/..."}
        }
        
        # 返回:
        {
            "text": "发现新漏洞 RCE漏洞", 
            "desp": "风险等级: 高危\n详情: https://github.com/..."
        }
    
    """
    if not data:
        return webhook_data
        
    # 将data扁平化为key-value形式
    flat_data = {}
    
    def flatten_dict(d, parent_key=''):
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                flatten_dict(v, new_key)
            else:
                flat_data[new_key] = v
    
    for section in ['cve', 'repo', 'gpt']:
        if section in data:
            flatten_dict(data[section], section)
    
    # 替换webhook_data中的变量
    if isinstance(webhook_data, dict):
        webhook_str = json.dumps(webhook_data)
        for k, v in flat_data.items():
            webhook_str = webhook_str.replace(f"{{{k}}}", str(v))
        return json.loads(webhook_str)
    elif isinstance(webhook_data, str):
        for k, v in flat_data.items():
            webhook_data = webhook_data.replace(f"{{{k}}}", str(v))
        return json.loads(webhook_data)

def send_webhook(data):
    webhook_url = get_config('WEBHOOK_URL')
    notify_type = get_config('NOTIFY_TYPE')
    p = f'template/{notify_type}.json'
    if not os.path.exists(p):
        logger.error(f"消息模板文件不存在: {p}")
        return
    webhook_data = open(p, 'r', encoding='utf-8').read()
    msg = parse_webhook_data(webhook_data, data)
    logger.debug(f"解析webhook_data: {msg}")
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # 使用json参数发送请求，requests会自动处理字典到JSON的转换
        response = requests.post(webhook_url, json=msg, headers=headers)
        response.raise_for_status()  # 抛出HTTP错误
        
        # 安全地尝试解析JSON响应
        response_data = response.json()

        logger.debug(f"Webhook sent: {webhook_url},response_data: {response_data},status: {response.status_code}")
    except Exception as e:
        logger.error(f"Webhook failed: {webhook_url}, error: {str(e)}")

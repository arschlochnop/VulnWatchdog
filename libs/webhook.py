import json
import os
import requests
from config import get_config
import logging

logger = logging.getLogger(__name__)


def parse_webhook_data(webhook_data, data):
    """
    解析webhook数据并替换变量

    Args:
        webhook_data: webhook消息模板,支持字符串或字典格式
                     模板中可使用{key}形式的变量,key为data中的字段路径
                     例如:
                     - {cve.title} - CVE标题
                     - {repo.html_url} - 仓库URL
                     - {gpt.risk} - GPT分析的风险等级

        data: 包含CVE、仓库、GPT分析结果的字典数据

    Returns:
        解析后的webhook数据
    """
    if not data:
        logger.warning("parse_webhook_data: data为空")
        return webhook_data

    logger.debug(f"parse_webhook_data: data keys = {list(data.keys())}")

    # 将data扁平化为key-value形式
    flat_data = {}

    def flatten_dict(d, parent_key=''):
        """递归扁平化字典"""
        if not isinstance(d, dict):
            logger.warning(f"flatten_dict: {parent_key} 不是字典类型: {type(d)}")
            return

        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                flatten_dict(v, new_key)
            else:
                flat_data[new_key] = v if v is not None else ''

    # 扁平化三个主要部分
    for section in ['cve', 'repo', 'gpt']:
        if section in data:
            logger.debug(f"处理section: {section}, type: {type(data[section])}")
            flatten_dict(data[section], section)
        else:
            logger.warning(f"data中缺少section: {section}")

    logger.debug(f"扁平化后的keys: {list(flat_data.keys())[:10]}...")  # 只显示前10个

    # 替换webhook_data中的变量
    if isinstance(webhook_data, dict):
        webhook_str = json.dumps(webhook_data, ensure_ascii=False)
    elif isinstance(webhook_data, str):
        webhook_str = webhook_data
    else:
        logger.error(f"webhook_data类型错误: {type(webhook_data)}")
        return webhook_data

    # 执行变量替换
    replaced_count = 0
    for k, v in flat_data.items():
        old_str = webhook_str
        # 转换值为字符串，处理None和特殊字符
        value_str = str(v) if v is not None else ''
        # JSON转义处理
        value_str = value_str.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

        webhook_str = webhook_str.replace(f"{{{k}}}", value_str)

        if webhook_str != old_str:
            replaced_count += 1
            logger.debug(f"替换变量: {{{k}}} -> {value_str[:50]}...")

    logger.info(f"变量替换完成: 共替换 {replaced_count} 个变量")

    # 解析为JSON
    try:
        return json.loads(webhook_str)
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {str(e)}")
        logger.error(f"问题内容: {webhook_str[:500]}...")
        return webhook_data

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

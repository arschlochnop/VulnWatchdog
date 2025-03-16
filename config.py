import os
import logging
from dotenv import load_dotenv


# 配置文件
DEBUG=False

load_dotenv()


# 是否启用通知功能
ENABLE_NOTIFY=True

# 通知类型,目前支持飞书(feishu),其他可参考飞书模板 template/feishu.json
NOTIFY_TYPE='feishu'

# 是否启用GPT功能进行漏洞分析
ENABLE_GPT=True

# GPT模型名称,使用Gemini 2.0 Flash版本
GPT_MODEL='gemini-2.0-flash'

# 是否启用漏洞信息搜索功能，需启用GPT分析
ENABLE_SEARCH=True

# 是否启用扩展搜索功能
ENABLE_EXTENDED=False

# 数据库URL
DB_URL='sqlite:///vulns.db'

if os.environ.get('DEBUG'):
    DEBUG = os.environ.get('DEBUG')

def get_config(env: str):
    config = {
        "DEBUG": 'DEBUG' if DEBUG =='true' else 'INFO',
        # 通知配置
        'ENABLE_NOTIFY': ENABLE_NOTIFY,
        'NOTIFY_TYPE': os.environ.get('NOTIFY_TYPE') if os.environ.get('NOTIFY_TYPE') else NOTIFY_TYPE,
        'WEBHOOK_URL': os.environ.get('WEBHOOK_URL'),
        # GPT配置
        'ENABLE_GPT': ENABLE_GPT,
        'GPT_SERVER_URL': os.environ.get('GPT_SERVER_URL'),
        'GPT_API_KEY': os.environ.get('GPT_API_KEY'),
        'GPT_MODEL': os.environ.get('GPT_MODEL') if os.environ.get('GPT_MODEL') else GPT_MODEL,
        # 搜索配置
        'ENABLE_SEARCH': ENABLE_SEARCH,
        'SEARXNG_URL': os.environ.get('SEARXNG_URL'),
        # 数据库配置
        'DB_URL': DB_URL,
        # 扩展搜索配置
        'ENABLE_EXTENDED': ENABLE_EXTENDED,
        # 仓库地址
        'GIT_URL': os.environ.get('GIT_URL', ''),
    }
    return config.get(env, '')

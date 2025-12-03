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
ENABLE_EXTENDED=True

# 是否启用仓库更新检测(基于commit SHA)
ENABLE_UPDATE_CHECK=True

# GitHub API Token 配置说明:
# 1. GH_TOKEN: 用户手工配置的 Personal Access Token (推荐，5000次/小时)
# 2. GITHUB_TOKEN: GitHub Actions 自动提供的 Token (1000次/小时)
# 3. 未配置: 使用未认证模式 (60次/小时)
# 优先级: GH_TOKEN > GITHUB_TOKEN > None
GITHUB_TOKEN=None

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
        # Token限制配置 (字符数，约等于tokens * 4)
        'MAX_CVE_INFO_CHARS': int(os.environ.get('MAX_CVE_INFO_CHARS', '1000')),
        'MAX_SEARCH_CHARS': int(os.environ.get('MAX_SEARCH_CHARS', '2000')),
        'MAX_POC_CODE_CHARS': int(os.environ.get('MAX_POC_CODE_CHARS', '3000')),
        'MAX_PROMPT_CHARS': int(os.environ.get('MAX_PROMPT_CHARS', '24000')),
        # 搜索配置
        'ENABLE_SEARCH': ENABLE_SEARCH,
        'SEARXNG_URL': os.environ.get('SEARXNG_URL'),  # 旧版单引擎配置 (已废弃)
        'SEARXNG_URLS': os.environ.get('SEARXNG_URLS'),  # 新版多引擎配置 (逗号分隔)
        # 数据库配置
        'DB_URL': DB_URL,
        # 扩展搜索配置
        'ENABLE_EXTENDED': ENABLE_EXTENDED,
        # 更新检测配置
        'ENABLE_UPDATE_CHECK': ENABLE_UPDATE_CHECK,
        # GitHub配置 (优先使用 GH_TOKEN，其次 GITHUB_TOKEN)
        'GITHUB_TOKEN': os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or GITHUB_TOKEN,
        # 仓库地址
        'GIT_URL': os.environ.get('GIT_URL', ''),
    }
    return config.get(env, '')

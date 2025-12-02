from datetime import datetime, timezone, timedelta
import json
import os
import time
import traceback
from config import get_config
from libs.utils import search_github, get_cve_info, ask_gpt, search_searxng, get_github_poc, write_to_markdown, get_latest_commit_sha
from libs.webhook import send_webhook
from models.models import get_db, CVE, Repository
import logging
import sys
from typing import List, Dict, Optional

# 配置日志
log_level = logging.DEBUG if get_config('DEBUG') == 'DEBUG' else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 设置第三方库的日志级别，避免输出过多DEBUG日志
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)

# 从配置文件加载功能开关
enable_gpt = get_config('ENABLE_GPT')
enable_notify = get_config('ENABLE_NOTIFY')
enable_search = get_config('ENABLE_SEARCH')
enable_extended = get_config('ENABLE_EXTENDED')
enable_update_check = get_config('ENABLE_UPDATE_CHECK')

def build_prompt(cve_info: Dict, search_results: List[Dict], poc_results_str: str) -> str:
    """
    构建发送给GPT的提示文本，智能控制总长度

    Args:
        cve_info: CVE漏洞信息字典
        search_results: 搜索结果列表
        poc_results_str: POC代码内容

    Returns:
        str: 格式化的提示文本
    """
    try:
        # Token限制配置 (从配置文件读取)
        MAX_CVE_INFO = get_config('MAX_CVE_INFO_CHARS')
        MAX_SEARCH = get_config('MAX_SEARCH_CHARS')
        MAX_POC_CODE = get_config('MAX_POC_CODE_CHARS')
        MAX_PROMPT = get_config('MAX_PROMPT_CHARS')

        # 格式化搜索结果并限制长度
        search_results_str = ""
        for i, result in enumerate(search_results):
            if len(search_results_str) >= MAX_SEARCH:
                break
            search_results_str += f"[webpage {i} begin] [title] {result.get('title', '')}\n [description] {result.get('content', '')}\n [link] {result.get('url', '')}\n [webpage {i} end]\n"

        # 截断搜索结果
        if len(search_results_str) > MAX_SEARCH:
            search_results_str = search_results_str[:MAX_SEARCH] + "\n...(搜索结果已截断)"

        if search_results_str:
            search_results_str = f"""
            ## 以下内容是基于此漏洞的搜索结果:
                {search_results_str}
            """

        # 限制CVE信息长度
        cve_info_str = json.dumps(cve_info)
        if len(cve_info_str) > MAX_CVE_INFO:
            # 保留关键字段
            limited_cve = {
                'id': cve_info.get('id', ''),
                'summary': cve_info.get('summary', '')[:500] if cve_info.get('summary') else '',
                'cvss': cve_info.get('cvss', ''),
            }
            cve_info_str = json.dumps(limited_cve)

        # 限制POC代码长度
        if len(poc_results_str) > MAX_POC_CODE:
            poc_results_str = poc_results_str[:MAX_POC_CODE] + "\n...(POC代码已截断，仅显示前3000字符)"
        
        # 记录各部分长度
        logger.info(f"Token控制 - CVE信息: {len(cve_info_str)} 字符")
        logger.info(f"Token控制 - 搜索结果: {len(search_results_str)} 字符")
        logger.info(f"Token控制 - POC代码: {len(poc_results_str)} 字符")

        # 构建完整提示文本
        prompt = f"""
      请根据以下漏洞信息、搜索结果和漏洞利用代码，评估漏洞利用的有效性、是否存在投毒风险，并分析漏洞利用方式。请注意以下几点：

    **信息来源：**

    *   **漏洞库信息：**
        ```
        {cve_info_str}
        ```
    *   **搜索引擎结果：**
        ```
        {search_results_str}
        ```
    *   **漏洞利用代码：**
        ```
        {poc_results_str}
        ```

    **你的角色：** 你是一名搜索助理和网络漏洞研究员。

    **任务：**

    1.  **有效性：**  判断提供的POC代码是否有效。
    2.  **投毒风险：**  分析POC代码内容,判断此仓库中是否存在作者隐藏的投毒代码,分析结果使用百分比。务必不要把POC验证的后门代码判定为投毒代码。
    3.  **利用方式：**  分析并总结漏洞的利用方式。
    4.  **排序优先级:** 搜索引擎结果 >  漏洞利用代码 > 漏洞库信息
    5.  **输出内容:** 务必使用中文
    6.  **markdown内容:** 务必使用markdown格式对提供的内容,围绕本次任务要求进行详细描述.
    **输出格式：**  你**必须**严格按照以下 **JSON** 格式输出，**不要包含任何额外的文字、说明或前缀/后缀**。JSON中的**所有键和字符串类型的值必须使用双引号**。请务必对特殊字符进行转义。

    **示例JSON:**```json
    {{
        "name": "CVE-2023-12345-ExampleApp-SQL注入",
        "type": "SQL注入",
        "app": "ExampleApp", 
        "risk": "高危，可能导致数据泄露和远程代码执行",
        "version": "<= 1.0",
        "condition": "需要网络访问和数据库端口开放",
        "poc_available": "是",
        "poison": "90%",
        "markdown": "该漏洞存在于ExampleApp的登录模块,攻击者可以通过构造恶意的SQL语句绕过身份验证..."
    }}
        """
        
        # 记录最终长度
        prompt_length = len(prompt)
        logger.info(f"最终提示文本长度: {prompt_length} 字符 (约 {prompt_length//4} tokens)")

        # Token警告
        if prompt_length > MAX_PROMPT:
            logger.warning(f"提示文本超出配置限制: {prompt_length}/{MAX_PROMPT} 字符 (约 {prompt_length//4} tokens)")

        # 调试日志
        logger.debug("提示文本构建完成")
        logger.debug(f"漏洞信息: {cve_info_str[:200]}...")
        logger.debug(f"搜索结果: {search_results_str[:200]}...")
        logger.debug(f"POC代码: {poc_results_str[:200]}...")
        
        return prompt
        
    except Exception as e:
        logger.error(f"构建提示文本失败: {str(e)}")
        logger.debug(traceback.format_exc())
        return None

def process_cve(cve_id: str, repo: Dict, engine) -> Dict:
    """
    处理单个CVE信息
    
    Args:
        cve_id: CVE编号
        repo: 仓库信息
        engine: 数据库连接
    """
    result = {}
    try:
        # 提取仓库基本信息
        repo_pushed_at = repo.get('pushed_at', '')
        repo_link = repo.get('html_url', '')
        repo_name = repo.get('name', '')
        repo_description = repo.get('description', '')
        repo_full_name = repo.get('full_name', '')
        
        logger.info(f"开始处理仓库: {repo_full_name}")

        # 检查仓库是否已存在
        repo_data = engine.query(Repository).filter(Repository.github_id == repo['id']).order_by(Repository.id.desc()).first()

        if repo_data:
            logger.info(f"仓库已存在: {repo_link}")

            # 启用更新检测
            if enable_update_check:
                # 通过commit SHA判断是否有更新
                latest_sha = get_latest_commit_sha(repo_link)

                if not latest_sha:
                    logger.warning(f"无法获取commit SHA,跳过处理: {repo_link}")
                    return result

                if repo_data.latest_commit_sha == latest_sha:
                    logger.info(f"仓库无更新 (SHA相同: {latest_sha[:8]}...),跳过处理")
                    return result
                else:
                    logger.info(f"仓库有更新 (旧SHA: {repo_data.latest_commit_sha[:8] if repo_data.latest_commit_sha else 'None'}... → 新SHA: {latest_sha[:8]}...)")
                    action_log = 'update'
            else:
                # 未启用更新检测,直接跳过已存在的仓库
                logger.info(f"更新检测未启用,跳过已存在的仓库")
                return result
        else:
            logger.info(f"发现新仓库: {repo_link}")
            action_log = 'new'
            latest_sha = None  # 新仓库,稍后获取SHA

        # 获取POC代码
        logger.info(f"获取POC代码: {repo_link}")
        code_prompt = get_github_poc(repo_link)
        if not code_prompt:
            logger.error(f"获取POC代码失败")
            return

        # 获取或创建CVE信息
        cve = engine.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            logger.info(f"获取CVE信息: {cve_id}")
            cve_info = get_cve_info(cve_id)
            if not cve_info:
                logger.error(f"获取CVE信息失败")
                cve_info = {}
            else:    
                try:
                    cve_data = CVE(
                        cve_id=cve_id,
                        title=cve_info.get('title'),
                        description=cve_info.get('description',{}).get('value'),
                        cve_data=cve_info
                    )
                    engine.add(cve_data)
                    engine.commit()
                    logger.info(f"保存CVE信息成功")
                except Exception as e:
                    logger.error(f"保存CVE信息失败: {str(e)}")
                    engine.rollback()
                
        else:
            cve_info = cve.cve_data
        result['cve'] = cve_info
        result['repo'] = repo

        # GPT分析
        gpt_results = None
        if enable_gpt:
            search_result = []
            if enable_search:
                logger.info(f"搜索漏洞相关信息: {cve_id}")
                search_result = search_searxng(f"{cve_id} Vulnerability Analysis")

            logger.info("构建GPT提示文本")
            # build_prompt内部会进行智能截断，不需要在这里预先截断
            prompt = build_prompt(cve_info, search_result, code_prompt)
            if not prompt:
                logger.error("构建提示文本失败")
                return result
                
            logger.info("请求GPT分析")
            gpt_results = ask_gpt(prompt)

            if gpt_results:
                logger.info(f"GPT 分析结果长度: {len(gpt_results)}")
                # 使用CVE年份作为目录结构 (YYYY/)
                import re
                match = re.match(r'CVE-(\d{4})-\d+', cve_id)
                if match:
                    cve_year = match.group(1)
                else:
                    # 如果无法解析CVE年份，使用当前年份
                    cve_year = datetime.now().strftime('%Y')
                    logger.warning(f"无法解析CVE年份: {cve_id}, 使用当前年份: {cve_year}")

                # 确保目录存在
                os.makedirs(f"data/{cve_year}", exist_ok=True)

                # 新的文件路径
                filepath = f"data/{cve_year}/{cve_id}-{repo_full_name.replace('/', '_')}.md"

                gpt_results.update({
                    'cve_id': cve_id,
                    'repo_name': repo_full_name,
                    'repo_url': repo_link,
                    'cve_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    'action_log': '新增' if action_log == 'new' else '更新',
                    'git_url': f"{get_config('GIT_URL')}/blob/main/{filepath}" if get_config('GIT_URL') else ''
                })
                result['gpt'] = gpt_results
                write_to_markdown(gpt_results, filepath)
                logger.info(f'生成分析报告: {filepath}')
            else:
                logger.error(f"GPT分析失败,返回结果: {gpt_results}")
                

        # 获取最新commit SHA (如果还没有)
        if latest_sha is None:
            latest_sha = get_latest_commit_sha(repo_link)
            if not latest_sha:
                logger.warning(f"无法获取commit SHA: {repo_link}")

        # 保存或更新仓库信息
        try:
            if action_log == 'update' and repo_data:
                # 更新现有记录
                repo_data.repo_pushed_at = repo_pushed_at
                repo_data.latest_commit_sha = latest_sha
                repo_data.gpt_analysis = gpt_results
                repo_data.action_log = action_log
                repo_data.repo_data = repo
                repo_data.updated_at = datetime.now()
                logger.info(f"更新仓库信息成功 (SHA: {latest_sha[:8] if latest_sha else 'None'}...)")
            else:
                # 新增记录
                new_repo_data = Repository(
                    github_id=repo['id'],
                    cve_id=cve_id,
                    name=repo_name,
                    description=repo_description,
                    url=repo_link,
                    action_log=action_log,
                    repo_data=repo,
                    repo_pushed_at=repo_pushed_at,
                    latest_commit_sha=latest_sha,
                    gpt_analysis=gpt_results
                )
                engine.add(new_repo_data)
                logger.info(f"新增仓库信息成功 (SHA: {latest_sha[:8] if latest_sha else 'None'}...)")

            engine.commit()
        except Exception as e:
            logger.error(f"保存仓库信息失败: {str(e)}")
            engine.rollback()
        

        # 发送通知
        # 判断仓库push时间是否为今天,统一时区,如果为当天则发送通知，否则只入库
        tz = timezone(timedelta(hours=8))  # UTC+8 for Asia/Shanghai
        today = datetime.now(tz).date()
        repo_date = datetime.strptime(repo_pushed_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).astimezone(tz).date()
        push_today = today == repo_date
        if enable_notify and push_today:
            logger.info("发送通知")
            send_webhook(result)
        return result

    except Exception as e:
        logger.error(f"处理CVE异常: {str(e)}")
        logger.debug(traceback.format_exc())


def main():
    """
    主函数:搜索并分析CVE漏洞信息

    """
    try:
        query = "CVE-20"
        logger.info(f"开始搜索CVE: {query}")
        
        # 搜索GitHub仓库
        cve_list, repo_list = search_github(query)
        if not repo_list:
            logger.warning("未找到相关仓库")
            return

        # 获取数据库连接
        engine = get_db()
        
        # 扩展搜索
        if enable_extended:
            logger.info("执行扩展搜索")
            for cve_id in cve_list:
                _, cve_items = search_github(cve_id)
                for item in cve_items:
                    if cve_id == item['cve_id']:
                        process_cve(cve_id, item['repo'], engine)
                time.sleep(10)
        else:
            # 处理每个仓库
            for repo in repo_list:
                try:    
                    cve_id = repo['cve_id']
                    logger.info(f"处理CVE: {cve_id}")
                    result = process_cve(cve_id, repo['repo'], engine)
                    time.sleep(10)
                except Exception as e:
                    logger.error(f"处理CVE异常: {str(e)} {repo}")
                    logger.debug(traceback.format_exc())
        logger.info("搜索分析完成")
        
    except Exception as e:
        logger.error(f"程序执行异常: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    logger.info(f"运行参数:")
    logger.info(f"  运行模式: {get_config('DEBUG')}")
    logger.info(f"  GPT 开关: {'启用' if get_config('ENABLE_GPT')==True else '禁用'}")
    logger.info(f"  搜索开关: {'启用' if get_config('ENABLE_SEARCH')==True else '禁用'}")
    logger.info(f"  扩展搜索开关: {'启用' if get_config('ENABLE_EXTENDED')==True else '禁用'}")
    logger.info(f"  更新检测开关: {'启用' if get_config('ENABLE_UPDATE_CHECK')==True else '禁用'}")
    logger.info(f"  通知开关: {'启用' if get_config('ENABLE_NOTIFY')==True else '禁用'}")
    logger.info(f"  通知类型: {get_config('NOTIFY_TYPE')}")
    main()

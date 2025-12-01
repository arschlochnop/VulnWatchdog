#!/usr/bin/env python3
"""
本地测试主程序

简化版的 main.py，用于快速测试新功能：
1. 监控模块集成
2. 临时文件清理机制
3. GPT解析鲁棒性
4. Commit SHA更新检测

使用方法：
    python test_main.py
"""

from datetime import datetime, timezone, timedelta
import json
import os
import time
import traceback
from config import get_config
from libs.utils import search_github, get_cve_info, ask_gpt, search_searxng, get_github_poc, write_to_markdown, get_latest_commit_sha
from libs.webhook import send_webhook
from libs.monitor import get_monitor, reset_monitor
from models.models import get_db, CVE, Repository
import logging
import sys
from typing import List, Dict, Optional

# 配置日志
logging.basicConfig(
    level=logging.DEBUG if get_config('DEBUG') else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 从配置文件加载功能开关
enable_gpt = get_config('ENABLE_GPT')
enable_notify = get_config('ENABLE_NOTIFY')
enable_search = get_config('ENABLE_SEARCH')
enable_extended = get_config('ENABLE_EXTENDED')
enable_update_check = get_config('ENABLE_UPDATE_CHECK')

# 获取监控实例
monitor = get_monitor()


def build_prompt(cve_info: Dict, search_results: List[Dict], poc_results_str: str) -> str:
    """构建发送给GPT的提示文本"""
    try:
        # 格式化搜索结果
        search_results_str = ""
        for i, result in enumerate(search_results):
            search_results_str += f"[webpage {i} begin] [title] {result.get('title', '')}\n [description] {result.get('content', '')}\n [link] {result.get('url', '')}\n [webpage {i} end]\n"

        if search_results_str:
            search_results_str = f"""
            ## 以下内容是基于此漏洞的搜索结果:
                {search_results_str}
            """
        cve_info = json.dumps(cve_info)

        # 构建完整提示文本
        prompt = f"""
      请根据以下漏洞信息、搜索结果和漏洞利用代码，评估漏洞利用的有效性、是否存在投毒风险，并分析漏洞利用方式。请注意以下几点：

    **信息来源：**

    *   **漏洞库信息：**
        ```
        {cve_info}
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

        logger.info(f"提示文本总长度: {len(prompt)}")
        return prompt

    except Exception as e:
        logger.error(f"构建提示文本失败: {str(e)}")
        monitor.record_error('prompt_build_failure', str(e))
        return None


def process_cve(cve_id: str, repo: Dict, engine) -> Dict:
    """
    处理单个CVE信息（带监控集成）
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
                monitor.record_update_check(has_update=False)  # 先假设无更新

                # 通过commit SHA判断是否有更新
                monitor.record_github_api_call()
                latest_sha = get_latest_commit_sha(repo_link)

                if not latest_sha:
                    logger.warning(f"无法获取commit SHA,跳过处理: {repo_link}")
                    monitor.record_github_api_call(success=False)
                    return result

                if repo_data.latest_commit_sha == latest_sha:
                    logger.info(f"仓库无更新 (SHA相同: {latest_sha[:8]}...),跳过处理")
                    monitor.record_repo_skipped()
                    return result
                else:
                    logger.info(f"仓库有更新 (旧SHA: {repo_data.latest_commit_sha[:8] if repo_data.latest_commit_sha else 'None'}... → 新SHA: {latest_sha[:8]}...)")
                    monitor.record_update_check(has_update=True)  # 更新检测命中
                    action_log = 'update'
            else:
                # 未启用更新检测,直接跳过已存在的仓库
                logger.info(f"更新检测未启用,跳过已存在的仓库")
                monitor.record_repo_skipped()
                return result
        else:
            logger.info(f"发现新仓库: {repo_link}")
            action_log = 'new'
            latest_sha = None

        # 获取POC代码（会触发临时文件创建和清理）
        logger.info(f"获取POC代码: {repo_link}")
        monitor.record_clone()  # 记录克隆开始
        code_prompt = get_github_poc(repo_link)
        if not code_prompt:
            logger.error(f"获取POC代码失败")
            monitor.record_clone(success=False)
            monitor.record_repo_failed()
            return result

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
                    monitor.record_error('cve_save_failure', str(e), {'cve_id': cve_id})
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
            prompt = build_prompt(cve_info, search_result, code_prompt[:5000])
            if not prompt:
                logger.error("构建提示文本失败")
                monitor.record_repo_failed()
                return result

            logger.info("请求GPT分析")
            monitor.record_gpt_call()
            gpt_results = ask_gpt(prompt)

            if gpt_results:
                logger.info(f"GPT 分析成功，结果长度: {len(str(gpt_results))}")

                # 使用CVE年份作为目录结构
                import re
                match = re.match(r'CVE-(\d{4})-\d+', cve_id)
                if match:
                    cve_year = match.group(1)
                else:
                    cve_year = datetime.now().strftime('%Y')
                    logger.warning(f"无法解析CVE年份: {cve_id}, 使用当前年份: {cve_year}")

                os.makedirs(f"data/{cve_year}", exist_ok=True)
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
                logger.error(f"GPT分析失败")
                monitor.record_gpt_call(success=False)
                monitor.record_repo_failed()
                return result

        # 获取最新commit SHA (如果还没有)
        if latest_sha is None:
            latest_sha = get_latest_commit_sha(repo_link)
            if not latest_sha:
                logger.warning(f"无法获取commit SHA: {repo_link}")

        # 保存或更新仓库信息
        try:
            if action_log == 'update' and repo_data:
                repo_data.repo_pushed_at = repo_pushed_at
                repo_data.latest_commit_sha = latest_sha
                repo_data.gpt_analysis = gpt_results
                repo_data.action_log = action_log
                repo_data.repo_data = repo
                repo_data.updated_at = datetime.now()
                logger.info(f"更新仓库信息成功 (SHA: {latest_sha[:8] if latest_sha else 'None'}...)")
                monitor.record_repo_updated()
            else:
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
                monitor.record_repo_new()

            engine.commit()
        except Exception as e:
            logger.error(f"保存仓库信息失败: {str(e)}")
            monitor.record_error('repo_save_failure', str(e), {'repo': repo_link})
            monitor.record_repo_failed()
            engine.rollback()

        # 发送通知
        tz = timezone(timedelta(hours=8))
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
        monitor.record_error('process_cve_failure', str(e), {'cve_id': cve_id, 'repo': repo.get('html_url')})
        monitor.record_repo_failed()


def main():
    """
    测试主函数：只处理少量CVE进行快速验证
    """
    try:
        # 重置监控器
        reset_monitor()

        logger.info("=" * 60)
        logger.info("开始本地测试")
        logger.info("=" * 60)
        logger.info(f"运行参数:")
        logger.info(f"  DEBUG模式: {get_config('DEBUG')}")
        logger.info(f"  GPT分析: {'启用' if enable_gpt else '禁用'}")
        logger.info(f"  搜索功能: {'启用' if enable_search else '禁用'}")
        logger.info(f"  扩展搜索: {'启用' if enable_extended else '禁用'}")
        logger.info(f"  更新检测: {'启用' if enable_update_check else '禁用'}")
        logger.info(f"  通知功能: {'启用' if enable_notify else '禁用'}")
        logger.info("=" * 60)

        # 限制搜索结果数量（测试用）
        query = "CVE-2024"  # 只搜索2024年的CVE
        logger.info(f"开始搜索CVE: {query}")

        monitor.record_github_api_call()
        cve_list, repo_list = search_github(query)

        if not repo_list:
            logger.warning("未找到相关仓库")
            return

        # 只处理前3个仓库（快速测试）
        test_limit = 3
        repo_list = repo_list[:test_limit]

        logger.info(f"找到 {len(cve_list)} 个CVE, {len(repo_list)} 个仓库")
        logger.info(f"测试模式：只处理前 {test_limit} 个仓库")

        monitor.record_cve_found(len(cve_list))
        monitor.record_repo_found(len(repo_list))

        # 获取数据库连接
        engine = get_db()

        # 处理每个仓库
        for idx, repo in enumerate(repo_list, 1):
            try:
                cve_id = repo['cve_id']
                logger.info(f"\n[{idx}/{len(repo_list)}] 处理CVE: {cve_id}")
                result = process_cve(cve_id, repo['repo'], engine)

                # 测试时减少延迟
                time.sleep(3)
            except Exception as e:
                logger.error(f"处理CVE异常: {str(e)} {repo}")
                logger.debug(traceback.format_exc())
                monitor.record_repo_failed()

        logger.info("\n" + "=" * 60)
        logger.info("测试完成")
        logger.info("=" * 60)

        # 打印监控摘要
        monitor.print_summary()

        # 健康检查
        health = monitor.check_health()
        logger.info("\n健康状态检查:")
        logger.info(f"  状态: {health['status']}")
        if health['warnings']:
            logger.warning(f"  警告: {health['warnings']}")

        # 保存监控数据
        monitor.save_to_file('test_monitor_result.json')

    except Exception as e:
        logger.error(f"程序执行异常: {traceback.format_exc()}")
        monitor.record_error('main_failure', str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()

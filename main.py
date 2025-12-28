from datetime import datetime, timezone, timedelta
import json
import os
import time
import traceback
from config import get_config
from libs.utils import search_github, get_cve_info, ask_gpt, search_searxng, get_github_poc, write_to_markdown, get_latest_commit_sha
from libs.webhook import send_webhook
from libs.gpt_analyzer import GPTAnalyzer  # 新增: GPT分析器
from libs.blacklist_manager import BlacklistManager  # 新增: 黑名单管理器
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
enable_cve_dedup = get_config('ENABLE_CVE_DEDUP')
enable_update_notify = get_config('ENABLE_UPDATE_NOTIFY')

# 初始化 GPT 分析器
gpt_analyzer = None
if enable_gpt:
    try:
        gpt_analyzer = GPTAnalyzer(
            api_key=get_config('GPT_API_KEY'),
            api_url=get_config('GPT_SERVER_URL'),
            model=get_config('GPT_MODEL'),
            max_cve_info_chars=get_config('MAX_CVE_INFO_CHARS'),
            max_search_chars=get_config('MAX_SEARCH_CHARS'),
            max_poc_code_chars=get_config('MAX_POC_CODE_CHARS')
        )
        logger.info("✓ GPT分析器初始化成功")
    except ValueError as e:
        logger.error(f"✗ GPT分析器初始化失败: {e}")
        enable_gpt = False

# 初始化黑名单管理器
blacklist_manager = None
try:
    blacklist_manager = BlacklistManager()
    logger.info("✓ 黑名单管理器初始化成功")
except Exception as e:
    logger.error(f"✗ 黑名单管理器初始化失败: {e}")
    blacklist_manager = None


def process_cve(cve_id: str, repo: Dict, engine, notified_cves_today: set) -> Dict:
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

        # 黑名单检查
        if blacklist_manager:
            allowed, reason = blacklist_manager.check_repository(repo)
            if not allowed:
                logger.warning(f"⚫ 仓库已被黑名单拦截: {repo_full_name} - {reason}")
                return result

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

        # GPT分析 (使用新的 GPTAnalyzer)
        gpt_results = None
        if enable_gpt and gpt_analyzer:
            search_result = []
            if enable_search:
                search_result = search_searxng(f"{cve_id}")

            logger.info("开始GPT分析 (GPTAnalyzer)")
            # 使用新的 GPTAnalyzer 进行分析
            analyzer_result = gpt_analyzer.analyze(cve_info, search_result, code_prompt)

            if analyzer_result['success'] and analyzer_result['pass_quality_check']:
                logger.info("✓ GPT分析成功且通过质量检查")

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

                # 直接写入 Markdown (GPTAnalyzer 已经生成好了)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(analyzer_result['markdown'])

                # 构建 gpt_results 用于向后兼容
                data = analyzer_result['data']
                gpt_results = {
                    'cve_id': cve_id,
                    'repo_name': repo_full_name,
                    'repo_url': repo_link,
                    'cve_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    'action_log': '新增' if action_log == 'new' else '更新',
                    'git_url': f"{get_config('GIT_URL')}/blob/main/{filepath}" if get_config('GIT_URL') else '',

                    # 添加15字段原始数据
                    **data,

                    # 向后兼容映射（旧字段名 -> 新字段名）
                    'type': data.get('vulnerability_type', ''),
                    'app': data.get('affected_product', ''),
                    'risk': data.get('severity', ''),
                    'version': data.get('affected_versions', ''),
                    'condition': data.get('exploit_conditions', ''),
                    'poc_available': f"{data.get('poc_quality', 0)}/10",
                    'poison': data.get('poisoning_risk', ''),
                }
                result['gpt'] = gpt_results
                logger.info(f'生成分析报告: {filepath}')
            elif analyzer_result['success'] and not analyzer_result['pass_quality_check']:
                logger.warning(f"✗ GPT分析完成但未通过质量检查: {'; '.join(analyzer_result['fail_reasons'])}")

                # 记录质量检查失败,可能触发自动拉黑
                if blacklist_manager:
                    data = analyzer_result.get('data', {})
                    quality_score = data.get('poc_quality')
                    poisoning_risk = data.get('poisoning_risk')

                    # 提取数值
                    import re
                    quality_val = None
                    risk_val = None

                    if quality_score is not None:
                        quality_match = re.search(r'(\d+)', str(quality_score))
                        if quality_match:
                            quality_val = int(quality_match.group(1))

                    if poisoning_risk is not None:
                        risk_match = re.search(r'(\d+)', str(poisoning_risk))
                        if risk_match:
                            risk_val = int(risk_match.group(1))

                    blacklist_manager.record_quality_check_failure(
                        repo,
                        quality_val,
                        risk_val,
                        analyzer_result['fail_reasons']
                    )
            else:
                logger.error(f"✗ GPT分析失败: {analyzer_result.get('error', '未知错误')}")
                

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

        # 只有GPT分析成功且当天推送才发送通知
        if enable_notify and push_today and gpt_results:
            # 检查1: 仓库更新推送开关
            if action_log == 'update' and not enable_update_notify:
                logger.info(f"⊘ 仓库更新不推送通知 (ENABLE_UPDATE_NOTIFY=False): {repo_link}")
            # 检查2: CVE去重开关
            elif enable_cve_dedup and cve_id in notified_cves_today:
                logger.info(f"⊘ CVE今日已推送,跳过重复推送 (ENABLE_CVE_DEDUP=True): {cve_id}")
            # 通过所有检查,发送通知
            else:
                logger.info(f"✓ 发送飞书通知: {cve_id} ({action_log})")
                send_webhook(result)
                # 记录已推送的CVE
                if enable_cve_dedup:
                    notified_cves_today.add(cve_id)
                    logger.debug(f"已推送CVE列表更新: {len(notified_cves_today)} 个CVE")
        elif enable_notify and push_today and not gpt_results:
            logger.warning(f"GPT分析失败，跳过通知推送: {repo_link}")
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

        # 初始化今日已推送CVE集合(用于去重)
        notified_cves_today = set()
        logger.info(f"初始化CVE去重机制: ENABLE_CVE_DEDUP={enable_cve_dedup}, ENABLE_UPDATE_NOTIFY={enable_update_notify}")

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
                        process_cve(cve_id, item['repo'], engine, notified_cves_today)
                time.sleep(10)
        else:
            # 处理每个仓库
            for repo in repo_list:
                try:
                    cve_id = repo['cve_id']
                    logger.info(f"处理CVE: {cve_id}")
                    result = process_cve(cve_id, repo['repo'], engine, notified_cves_today)
                    time.sleep(10)
                except Exception as e:
                    logger.error(f"处理CVE异常: {str(e)} {repo}")
                    logger.debug(traceback.format_exc())
        logger.info("搜索分析完成")

        # 打印推送统计信息
        logger.info("=" * 50)
        logger.info(f"📊 本次运行推送统计:")
        logger.info(f"  - 已推送CVE数量: {len(notified_cves_today)}")
        if notified_cves_today:
            logger.info(f"  - 推送CVE列表: {', '.join(sorted(notified_cves_today))}")
        logger.info("=" * 50)

        # 打印黑名单统计信息
        if blacklist_manager:
            blacklist_manager.print_statistics()

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

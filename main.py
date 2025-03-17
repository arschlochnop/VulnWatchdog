import json
import time
import traceback
from config import get_config
from libs.utils import search_github, get_cve_info, ask_gpt, search_searxng, get_github_poc, write_to_markdown
from libs.webhook import send_webhook
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

def build_prompt(cve_info: Dict, search_results: List[Dict], poc_results_str: str) -> str:
    """
    构建发送给GPT的提示文本
    
    Args:
        cve_info: CVE漏洞信息字典
        search_results: 搜索结果列表
        poc_results_str: POC代码内容
        
    Returns:
        str: 格式化的提示文本
    """
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
        
        # 记录各部分长度
        logger.info(f"提示文本总长度: {len(prompt)}")
        logger.info(f"漏洞信息长度: {len(cve_info)}")
        logger.info(f"搜索结果长度: {len(search_results_str)}")
        logger.info(f"POC代码长度: {len(poc_results_str)}")
        
        # 调试日志
        logger.debug("提示文本构建完成")
        logger.debug(f"漏洞信息: {cve_info}")
        logger.debug(f"搜索结果: {search_results_str}")
        logger.debug(f"POC代码: {poc_results_str}")
        
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
            # 如果仓库已存在,则跳过处理,有的仓库无法判断是否更新
            # https://github.com/Mukesh-blend/CVE-2025-21333-POC
            #TODO 每次访问都会给出新的repo_pushed_at，所以无法判断是否更新，先停掉更新判断
            return result
            same_repo_data = engine.query(Repository).filter(
                Repository.github_id == repo['id'],
                Repository.repo_pushed_at == repo_pushed_at
            ).first()
            
            if same_repo_data:
                logger.info(f"仓库数据未更新,跳过处理: {repo_link}")
                return
            else:
                logger.info(f"仓库有更新: {repo_link}")
                action_log = 'update'
        else:
            logger.info(f"发现新仓库: {repo_link}")
            action_log = 'new'

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
                return result
                
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
                return result
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
                return result
                
            logger.info("请求GPT分析")
            gpt_results = ask_gpt(prompt)
            logger.info(f"GPT 分析结果长度: {len(gpt_results)}")

            if gpt_results:
                filepath = f"data/markdown/{cve_id}-{repo_full_name.replace('/', '_')}.md"
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
                

        # 保存仓库信息
        try:
            repo_data = Repository(
                github_id=repo['id'],
                cve_id=cve_id,
                name=repo_name,
                description=repo_description,
                url=repo_link,
                action_log=action_log,
                repo_data=repo,
                repo_pushed_at=repo_pushed_at,
                gpt_analysis=gpt_results
            )
            engine.add(repo_data)
            engine.commit()
            logger.info("保存仓库信息成功")
        except Exception as e:
            logger.error(f"保存仓库信息失败: {str(e)}")
            engine.rollback()
        

                # 发送通知
        if enable_notify:
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
                        repo_list.append(item['repo'])
                time.sleep(10)

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
    logger.info(f"  通知开关: {'启用' if get_config('ENABLE_NOTIFY')==True else '禁用'}")
    logger.info(f"  通知类型: {get_config('NOTIFY_TYPE')}")
    main()

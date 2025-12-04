#!/usr/bin/env python3
"""
GPT Prompt 测试工具

用途: 测试精简版 Prompt 效果
"""

import os
import sys
import argparse
import logging

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from libs.gpt_analyzer import GPTAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def quick_test():
    """快速测试 - 使用模拟数据"""

    logger.info("="*80)
    logger.info("GPT Analyzer 快速测试")
    logger.info("="*80)

    # 模拟CVE信息
    cve_info = {
        'id': 'CVE-2025-25256',
        'summary': 'FortiSIEM 命令注入漏洞，允许未经身份验证的远程代码执行',
        'cvss': '9.8'
    }

    # 模拟搜索结果
    search_results = [
        {
            'title': 'FortiSIEM CVE-2025-25256 远程代码执行漏洞分析',
            'content': 'FortiSIEM 6.1.0-7.3.1版本存在命令注入漏洞，攻击者可通过7900端口发送恶意请求执行任意命令',
            'url': 'https://example.com/analysis'
        }
    ]

    # 模拟POC代码
    poc_code = """
# FortiSIEM CVE-2025-25256 远程代码执行 PoC

import requests

def exploit(target_url):
    payload = {
        'cmd': 'whoami'
    }
    response = requests.post(f"{target_url}:7900/api/v1/exec", json=payload)
    return response.text

# Usage
result = exploit("http://192.168.1.100")
print(result)
"""

    # 创建分析器
    try:
        analyzer = GPTAnalyzer()

        # 执行分析
        logger.info("\n开始分析...")
        result = analyzer.analyze(cve_info, search_results, poc_code)

        # 显示结果
        logger.info("\n" + "="*80)
        logger.info("分析结果")
        logger.info("="*80)

        if result['success']:
            logger.info(f"✅ 分析成功!")
            logger.info(f"质量检查: {'✅ 通过' if result['pass_quality_check'] else '❌ 失败'}")

            if not result['pass_quality_check']:
                logger.warning(f"失败原因: {'; '.join(result['fail_reasons'])}")

            # 显示字段信息
            data = result['data']
            logger.info("\n" + "-"*80)
            logger.info("14字段数据:")
            logger.info("-"*80)
            for field in GPTAnalyzer.REQUIRED_FIELDS:
                value = data.get(field, 'N/A')
                # 截断长文本
                if isinstance(value, str) and len(value) > 100:
                    value = value[:100] + "..."
                logger.info(f"  {field}: {value}")

            # 显示Markdown
            logger.info("\n" + "-"*80)
            logger.info("Markdown输出:")
            logger.info("-"*80)
            logger.info(result['markdown'][:500] + "...")

            # 保存到文件
            output_file = "test_output.md"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result['markdown'])
            logger.info(f"\n完整Markdown已保存到: {output_file}")

        else:
            logger.error(f"❌ 分析失败: {result.get('error', '未知错误')}")

    except ValueError as e:
        logger.error(f"配置错误: {e}")
        logger.info("\n请设置以下环境变量:")
        logger.info("  export GPT_API_KEY=\"your-api-key\"")
        logger.info("  export GPT_SERVER_URL=\"https://api.openai.com/v1/chat/completions\"")
        logger.info("  export GPT_MODEL=\"gemini-2.5-flash\"  # 可选")
        sys.exit(1)
    except Exception as e:
        logger.error(f"测试失败: {e}", exc_info=True)
        sys.exit(1)


def custom_test(cve_id, repo_name, readme_file, code_file, search_file):
    """自定义测试 - 使用实际文件"""

    logger.info("="*80)
    logger.info("GPT Analyzer 自定义测试")
    logger.info("="*80)
    logger.info(f"CVE: {cve_id}")
    logger.info(f"仓库: {repo_name}")
    logger.info("="*80)

    # 读取README
    readme_content = ""
    if readme_file and os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            readme_content = f.read()
        logger.info(f"✓ README文件: {readme_file} ({len(readme_content)} 字符)")

    # 读取代码
    code_content = ""
    if code_file and os.path.exists(code_file):
        with open(code_file, 'r', encoding='utf-8') as f:
            code_content = f.read()
        logger.info(f"✓ 代码文件: {code_file} ({len(code_content)} 字符)")

    # 读取搜索结果
    search_results = []
    if search_file and os.path.exists(search_file):
        with open(search_file, 'r', encoding='utf-8') as f:
            search_content = f.read()
        search_results = [
            {
                'title': f'搜索结果 - {cve_id}',
                'content': search_content[:500],
                'url': 'N/A'
            }
        ]
        logger.info(f"✓ 搜索结果: {search_file} ({len(search_content)} 字符)")

    # 构建CVE信息
    cve_info = {
        'id': cve_id,
        'summary': readme_content[:500] if readme_content else '',
        'cvss': 'N/A'
    }

    # POC代码
    poc_code = f"# README\n{readme_content}\n\n# Code\n{code_content}"

    # 创建分析器
    try:
        analyzer = GPTAnalyzer()

        # 执行分析
        logger.info("\n开始分析...")
        result = analyzer.analyze(cve_info, search_results, poc_code)

        # 显示结果
        logger.info("\n" + "="*80)
        logger.info("分析结果")
        logger.info("="*80)

        if result['success']:
            logger.info(f"✅ 分析成功!")
            logger.info(f"质量检查: {'✅ 通过' if result['pass_quality_check'] else '❌ 失败'}")

            if not result['pass_quality_check']:
                logger.warning(f"失败原因: {'; '.join(result['fail_reasons'])}")

            # 保存到文件
            output_file = f"test_output_{cve_id.replace('/', '_')}.md"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result['markdown'])
            logger.info(f"\nMarkdown已保存到: {output_file}")

        else:
            logger.error(f"❌ 分析失败: {result.get('error', '未知错误')}")

    except ValueError as e:
        logger.error(f"配置错误: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"测试失败: {e}", exc_info=True)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='GPT Prompt 测试工具')

    # 测试模式
    parser.add_argument('--quick-test', action='store_true',
                        help='快速测试 (使用模拟数据)')

    # 自定义测试参数
    parser.add_argument('--cve', type=str,
                        help='CVE编号 (如: CVE-2025-25256)')
    parser.add_argument('--repo', type=str,
                        help='仓库名称 (如: user/repo)')
    parser.add_argument('--readme', type=str,
                        help='README文件路径')
    parser.add_argument('--code', type=str,
                        help='POC代码文件路径')
    parser.add_argument('--search', type=str,
                        help='搜索结果文件路径')

    args = parser.parse_args()

    if args.quick_test:
        quick_test()
    elif args.cve and args.repo:
        custom_test(args.cve, args.repo, args.readme, args.code, args.search)
    else:
        parser.print_help()
        print("\n示例用法:")
        print("  # 快速测试")
        print("  python tools/test_gpt_prompt.py --quick-test")
        print("\n  # 自定义测试")
        print("  python tools/test_gpt_prompt.py \\")
        print("    --cve CVE-2025-25256 \\")
        print("    --repo user/repo \\")
        print("    --readme /path/to/README.md \\")
        print("    --code /path/to/exploit.py \\")
        print("    --search /path/to/search.txt")


if __name__ == '__main__':
    main()

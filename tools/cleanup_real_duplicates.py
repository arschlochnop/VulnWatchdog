#!/usr/bin/env python3
"""
清理年份目录中真正包含重复合并标记的损坏文件
"""

import os
import re
import argparse
from pathlib import Path

def find_corrupted_files(data_dir: str = './data', dry_run: bool = True):
    """查找包含重复合并标记的文件"""
    corrupted_files = []

    # 遍历所有年份目录（不包括by-cve）
    for year_dir in Path(data_dir).glob('20*'):
        if not year_dir.is_dir():
            continue

        print(f"扫描 {year_dir.name} 年份...")

        for md_file in year_dir.glob('*.md'):
            if md_file.name == 'README.md':
                continue

            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 统计合并标记出现次数
                merge_markers = re.findall(r'📦 该CVE有.*?个相关POC仓库', content)
                marker_count = len(merge_markers)

                # 如果出现多次，说明有重复
                if marker_count > 1:
                    file_size = md_file.stat().st_size
                    corrupted_files.append({
                        'path': md_file,
                        'marker_count': marker_count,
                        'size': file_size
                    })
                    print(f"  ⚠️  {md_file.name}: {marker_count}个重复标记, {file_size}字节")

            except Exception as e:
                print(f"  ❌ 读取失败 {md_file.name}: {e}")

    return corrupted_files


def delete_files(files: list, dry_run: bool = True):
    """删除文件"""
    if not files:
        print("\n✨ 没有发现损坏的文件!")
        return

    print(f"\n发现 {len(files)} 个损坏的文件:")
    for file_info in files:
        print(f"  - {file_info['path'].relative_to('./data')}: {file_info['marker_count']}个重复")

    if dry_run:
        print("\n⚠️  试运行模式 - 未删除任何文件")
        print("使用 --delete 参数执行实际删除")
        return

    print(f"\n🗑️  开始删除 {len(files)} 个文件...")
    deleted = 0
    for file_info in files:
        try:
            file_info['path'].unlink()
            deleted += 1
            print(f"  ✓ 已删除: {file_info['path'].name}")
        except Exception as e:
            print(f"  ✗ 删除失败 {file_info['path'].name}: {e}")

    print(f"\n✅ 完成! 共删除 {deleted} 个文件")


def main():
    parser = argparse.ArgumentParser(description='清理真正的重复内容文件')
    parser.add_argument('--delete', action='store_true', help='实际执行删除操作')
    parser.add_argument('--data-dir', default='./data', help='数据目录路径')
    args = parser.parse_args()

    dry_run = not args.delete

    print("=" * 70)
    print("CVE分析文档重复内容清理工具 (年份目录版)")
    print(f"模式: {'实际删除' if not dry_run else '试运行 (不会实际删除)'}")
    print("=" * 70)
    print()

    # 查找损坏文件
    corrupted_files = find_corrupted_files(args.data_dir, dry_run)

    # 删除文件
    delete_files(corrupted_files, dry_run)

    print()


if __name__ == '__main__':
    main()

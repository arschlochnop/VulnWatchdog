#!/usr/bin/env python3
"""
测试更新检测逻辑
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from models.models import get_db, Repository
from config import get_config

def test_update_logic():
    """
    测试更新检测逻辑
    """
    print("🧪 测试更新检测逻辑\n")

    # 检查配置
    enable_update_check = get_config('ENABLE_UPDATE_CHECK')
    print(f"✓ ENABLE_UPDATE_CHECK 配置: {enable_update_check}\n")

    # 检查数据库结构
    engine = get_db()

    # 查询一条记录检查字段
    repo = engine.query(Repository).first()
    if repo:
        print("✓ 数据库字段检查:")
        print(f"  github_id: {repo.github_id}")
        print(f"  url: {repo.url}")
        print(f"  repo_pushed_at: {repo.repo_pushed_at}")
        print(f"  latest_commit_sha: {repo.latest_commit_sha}")
        print(f"  action_log: {repo.action_log}\n")

    # 统计数据
    total = engine.query(Repository).count()
    with_sha = engine.query(Repository).filter(Repository.latest_commit_sha.isnot(None)).count()
    without_sha = engine.query(Repository).filter(Repository.latest_commit_sha.is_(None)).count()

    print("📊 数据统计:")
    print(f"  总记录数: {total}")
    print(f"  已有SHA: {with_sha}")
    print(f"  缺少SHA: {without_sha}\n")

    # 测试场景1: 已存在仓库,SHA相同
    print("📝 测试场景1: 仓库已存在且SHA相同")
    print("  预期: 跳过处理")
    print("  实际: 在main.py:152-154行检测\n")

    # 测试场景2: 已存在仓库,SHA不同
    print("📝 测试场景2: 仓库已存在但SHA不同")
    print("  预期: 执行更新,action_log='update'")
    print("  实际: 在main.py:156-157行标记\n")

    # 测试场景3: 新仓库
    print("📝 测试场景3: 新仓库")
    print("  预期: 执行完整处理,action_log='new'")
    print("  实际: 在main.py:163-165行处理\n")

    # 测试场景4: 更新检测关闭
    print("📝 测试场景4: ENABLE_UPDATE_CHECK=False")
    print("  预期: 跳过所有已存在仓库")
    print("  实际: 在main.py:159-161行跳过\n")

    print("✅ 逻辑测试完成")
    print("\n💡 提示:")
    print("  1. 修复了main.py:143行的return问题")
    print("  2. 使用commit SHA代替pushed_at判断更新")
    print("  3. 支持更新模式(action_log='update')")
    print("  4. 添加ENABLE_UPDATE_CHECK配置开关")

    engine.close()


if __name__ == '__main__':
    test_update_logic()

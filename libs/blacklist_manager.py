#!/usr/bin/env python3
"""
黑名单管理器 - VulnWatchdog
用于管理低质量POC作者和恶意仓库的黑名单
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class BlacklistEntry:
    """黑名单条目"""
    identifier: str  # username 或 full_name
    reason: str
    added_date: str
    added_by: str  # 'auto' 或 'manual'
    fail_count: int = 0
    last_quality_score: Optional[int] = None
    last_poisoning_risk: Optional[int] = None
    notes: str = ""


@dataclass
class WhitelistEntry:
    """白名单条目"""
    identifier: str
    reason: str
    added_date: str
    notes: str = ""


class BlacklistManager:
    """黑名单管理器"""

    def __init__(self, config_path: str = "config/blacklist.json"):
        """
        初始化黑名单管理器

        Args:
            config_path: 黑名单配置文件路径
        """
        self.config_path = Path(config_path)
        self.data = self._load_config()
        self.settings = self.data.get('settings', {})
        self.blacklist = self.data.get('blacklist', {})
        self.whitelist = self.data.get('whitelist', {})
        self.statistics = self.data.get('statistics', {})

        logger.info(f"黑名单管理器已初始化: {len(self.blacklist.get('authors', []))} 个作者, "
                   f"{len(self.blacklist.get('repositories', []))} 个仓库")

    def _load_config(self) -> Dict:
        """加载黑名单配置"""
        if not self.config_path.exists():
            logger.warning(f"黑名单配置文件不存在: {self.config_path}, 使用默认配置")
            return self._get_default_config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.info(f"✓ 加载黑名单配置: {self.config_path}")
                return data
        except Exception as e:
            logger.error(f"加载黑名单配置失败: {e}, 使用默认配置")
            return self._get_default_config()

    def _get_default_config(self) -> Dict:
        """获取默认配置"""
        return {
            "version": "1.0.0",
            "settings": {
                "auto_blacklist_enabled": True,
                "auto_blacklist_thresholds": {
                    "min_quality_score": 3,
                    "max_poisoning_risk": 70,
                    "min_fail_count": 3
                }
            },
            "blacklist": {"authors": [], "repositories": [], "cves": []},
            "whitelist": {"authors": [], "repositories": []},
            "statistics": {
                "total_blocked": 0,
                "blocked_by_author": 0,
                "blocked_by_repository": 0,
                "auto_blacklisted_authors": 0,
                "auto_blacklisted_repositories": 0
            }
        }

    def _save_config(self):
        """保存黑名单配置"""
        try:
            self.data['last_updated'] = datetime.now().isoformat() + 'Z'
            self.data['blacklist'] = self.blacklist
            self.data['whitelist'] = self.whitelist
            self.data['statistics'] = self.statistics

            # 确保目录存在
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            logger.debug(f"黑名单配置已保存: {self.config_path}")
        except Exception as e:
            logger.error(f"保存黑名单配置失败: {e}")

    def is_author_blacklisted(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        检查作者是否在黑名单中

        Args:
            username: GitHub用户名

        Returns:
            (是否拉黑, 原因) 元组
        """
        # 先检查白名单
        for entry in self.whitelist.get('authors', []):
            if entry['username'].lower() == username.lower():
                logger.debug(f"作者 {username} 在白名单中,跳过检查")
                return False, None

        # 检查黑名单
        for entry in self.blacklist.get('authors', []):
            if entry['username'].lower() == username.lower():
                reason = f"作者已拉黑: {entry.get('reason', '未知原因')}"
                logger.info(f"✗ {reason}")
                self.statistics['blocked_by_author'] = self.statistics.get('blocked_by_author', 0) + 1
                self.statistics['total_blocked'] = self.statistics.get('total_blocked', 0) + 1
                return True, reason

        return False, None

    def is_repository_blacklisted(self, full_name: str) -> Tuple[bool, Optional[str]]:
        """
        检查仓库是否在黑名单中

        Args:
            full_name: 仓库全名 (owner/repo)

        Returns:
            (是否拉黑, 原因) 元组
        """
        # 先检查白名单
        for entry in self.whitelist.get('repositories', []):
            if entry['full_name'].lower() == full_name.lower():
                logger.debug(f"仓库 {full_name} 在白名单中,跳过检查")
                return False, None

        # 检查黑名单
        for entry in self.blacklist.get('repositories', []):
            if entry['full_name'].lower() == full_name.lower():
                reason = f"仓库已拉黑: {entry.get('reason', '未知原因')}"
                logger.info(f"✗ {reason}")
                self.statistics['blocked_by_repository'] = self.statistics.get('blocked_by_repository', 0) + 1
                self.statistics['total_blocked'] = self.statistics.get('total_blocked', 0) + 1
                return True, reason

        return False, None

    def is_cve_blacklisted(self, cve_id: str) -> Tuple[bool, Optional[str]]:
        """
        检查CVE是否在黑名单中

        Args:
            cve_id: CVE编号

        Returns:
            (是否拉黑, 原因) 元组
        """
        for entry in self.blacklist.get('cves', []):
            if entry['cve_id'].upper() == cve_id.upper():
                reason = f"CVE已拉黑: {entry.get('reason', '未知原因')}"
                logger.info(f"✗ {reason}")
                self.statistics['blocked_by_cve'] = self.statistics.get('blocked_by_cve', 0) + 1
                self.statistics['total_blocked'] = self.statistics.get('total_blocked', 0) + 1
                return True, reason

        return False, None

    def check_repository(self, repo: Dict) -> Tuple[bool, Optional[str]]:
        """
        综合检查仓库(作者+仓库+CVE)

        Args:
            repo: GitHub仓库信息字典

        Returns:
            (是否允许, 拒绝原因) 元组
        """
        full_name = repo.get('full_name', '')
        owner = repo.get('owner', {}).get('login', '')

        # 从仓库名提取CVE
        cve_match = re.search(r'CVE-\d{4}-\d+', full_name, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        # 1. 检查作者
        is_blocked, reason = self.is_author_blacklisted(owner)
        if is_blocked:
            return False, reason

        # 2. 检查仓库
        is_blocked, reason = self.is_repository_blacklisted(full_name)
        if is_blocked:
            return False, reason

        # 3. 检查CVE
        if cve_id:
            is_blocked, reason = self.is_cve_blacklisted(cve_id)
            if is_blocked:
                return False, reason

        return True, None

    def record_quality_check_failure(self, repo: Dict, quality_score: Optional[int],
                                     poisoning_risk: Optional[int], fail_reasons: List[str]):
        """
        记录质量检查失败,并根据阈值自动拉黑

        Args:
            repo: 仓库信息
            quality_score: POC质量评分 (0-10)
            poisoning_risk: 投毒风险 (0-100%)
            fail_reasons: 失败原因列表
        """
        if not self.settings.get('auto_blacklist_enabled', True):
            return

        full_name = repo.get('full_name', '')
        owner = repo.get('owner', {}).get('login', '')
        thresholds = self.settings.get('auto_blacklist_thresholds', {})

        # 检查是否需要拉黑作者
        if owner:
            author_entry = self._find_author_entry(owner)
            if not author_entry:
                # 创建新条目
                author_entry = {
                    'username': owner,
                    'reason': '',
                    'added_date': datetime.now().strftime('%Y-%m-%d'),
                    'added_by': 'tracking',  # 跟踪中
                    'fail_count': 0,
                    'last_quality_score': quality_score,
                    'last_poisoning_risk': poisoning_risk,
                    'notes': ''
                }

            # 更新失败计数和最新评分
            author_entry['fail_count'] = author_entry.get('fail_count', 0) + 1
            author_entry['last_quality_score'] = quality_score
            author_entry['last_poisoning_risk'] = poisoning_risk

            # 判断是否达到拉黑阈值
            should_blacklist = False
            blacklist_reason = []

            if quality_score is not None and quality_score < thresholds.get('min_quality_score', 3):
                blacklist_reason.append(f"POC质量持续过低(最近评分: {quality_score}/10)")
                should_blacklist = True

            if poisoning_risk is not None and poisoning_risk > thresholds.get('max_poisoning_risk', 70):
                blacklist_reason.append(f"投毒风险持续过高(最近风险: {poisoning_risk}%)")
                should_blacklist = True

            if author_entry['fail_count'] >= thresholds.get('min_fail_count', 3):
                blacklist_reason.append(f"连续失败{author_entry['fail_count']}次")
                should_blacklist = True

            if should_blacklist and author_entry.get('added_by') != 'blacklist':
                # 自动拉黑
                author_entry['added_by'] = 'auto'
                author_entry['reason'] = '; '.join(blacklist_reason)
                author_entry['added_date'] = datetime.now().strftime('%Y-%m-%d')
                author_entry['notes'] = f"自动拉黑 - 失败原因: {', '.join(fail_reasons)}"

                # 添加到黑名单
                if 'authors' not in self.blacklist:
                    self.blacklist['authors'] = []

                # 移除旧条目(如果存在)
                self.blacklist['authors'] = [e for e in self.blacklist['authors']
                                             if e['username'].lower() != owner.lower()]
                self.blacklist['authors'].append(author_entry)

                self.statistics['auto_blacklisted_authors'] = self.statistics.get('auto_blacklisted_authors', 0) + 1

                logger.warning(f"⚫ 自动拉黑作者: {owner} - {author_entry['reason']}")
                self._save_config()

    def _find_author_entry(self, username: str) -> Optional[Dict]:
        """查找作者条目"""
        for entry in self.blacklist.get('authors', []):
            if entry['username'].lower() == username.lower():
                return entry
        return None

    def add_author_to_blacklist(self, username: str, reason: str, notes: str = ""):
        """
        手动添加作者到黑名单

        Args:
            username: GitHub用户名
            reason: 拉黑原因
            notes: 备注
        """
        # 检查是否已存在
        if self._find_author_entry(username):
            logger.warning(f"作者 {username} 已在黑名单中")
            return

        entry = {
            'username': username,
            'reason': reason,
            'added_date': datetime.now().strftime('%Y-%m-%d'),
            'added_by': 'manual',
            'fail_count': 0,
            'notes': notes
        }

        if 'authors' not in self.blacklist:
            self.blacklist['authors'] = []

        self.blacklist['authors'].append(entry)
        logger.info(f"✓ 添加作者到黑名单: {username}")
        self._save_config()

    def remove_author_from_blacklist(self, username: str):
        """
        从黑名单移除作者

        Args:
            username: GitHub用户名
        """
        if 'authors' not in self.blacklist:
            return

        original_count = len(self.blacklist['authors'])
        self.blacklist['authors'] = [e for e in self.blacklist['authors']
                                      if e['username'].lower() != username.lower()]

        if len(self.blacklist['authors']) < original_count:
            logger.info(f"✓ 从黑名单移除作者: {username}")
            self._save_config()
        else:
            logger.warning(f"作者 {username} 不在黑名单中")

    def add_repository_to_blacklist(self, full_name: str, reason: str, notes: str = ""):
        """
        手动添加仓库到黑名单

        Args:
            full_name: 仓库全名 (owner/repo)
            reason: 拉黑原因
            notes: 备注
        """
        entry = {
            'full_name': full_name,
            'reason': reason,
            'added_date': datetime.now().strftime('%Y-%m-%d'),
            'added_by': 'manual',
            'notes': notes
        }

        if 'repositories' not in self.blacklist:
            self.blacklist['repositories'] = []

        # 检查是否已存在
        for e in self.blacklist['repositories']:
            if e['full_name'].lower() == full_name.lower():
                logger.warning(f"仓库 {full_name} 已在黑名单中")
                return

        self.blacklist['repositories'].append(entry)
        logger.info(f"✓ 添加仓库到黑名单: {full_name}")
        self._save_config()

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        stats = self.statistics.copy()
        stats['blacklist_authors_count'] = len(self.blacklist.get('authors', []))
        stats['blacklist_repositories_count'] = len(self.blacklist.get('repositories', []))
        stats['blacklist_cves_count'] = len(self.blacklist.get('cves', []))
        stats['whitelist_authors_count'] = len(self.whitelist.get('authors', []))
        stats['whitelist_repositories_count'] = len(self.whitelist.get('repositories', []))
        return stats

    def print_statistics(self):
        """打印统计信息"""
        stats = self.get_statistics()
        logger.info("=" * 50)
        logger.info("黑名单统计信息")
        logger.info("=" * 50)
        logger.info(f"黑名单作者数: {stats['blacklist_authors_count']}")
        logger.info(f"黑名单仓库数: {stats['blacklist_repositories_count']}")
        logger.info(f"黑名单CVE数: {stats['blacklist_cves_count']}")
        logger.info(f"白名单作者数: {stats['whitelist_authors_count']}")
        logger.info(f"白名单仓库数: {stats['whitelist_repositories_count']}")
        logger.info("-" * 50)
        logger.info(f"总拦截次数: {stats.get('total_blocked', 0)}")
        logger.info(f"  - 按作者拦截: {stats.get('blocked_by_author', 0)}")
        logger.info(f"  - 按仓库拦截: {stats.get('blocked_by_repository', 0)}")
        logger.info(f"  - 按CVE拦截: {stats.get('blocked_by_cve', 0)}")
        logger.info(f"自动拉黑作者: {stats.get('auto_blacklisted_authors', 0)}")
        logger.info(f"自动拉黑仓库: {stats.get('auto_blacklisted_repositories', 0)}")
        logger.info("=" * 50)

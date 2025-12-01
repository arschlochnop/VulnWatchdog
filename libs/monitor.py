"""
监控和告警模块

功能:
- 运行时统计和监控
- 错误追踪和告警
- 性能指标收集
- 健康状态检查
"""

import logging
import time
from datetime import datetime
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


@dataclass
class MonitorMetrics:
    """监控指标数据类"""

    # 运行统计
    start_time: float = field(default_factory=time.time)
    total_cves: int = 0
    total_repos: int = 0

    # 处理统计
    new_repos: int = 0
    updated_repos: int = 0
    skipped_repos: int = 0  # 无更新跳过的仓库

    # 成功/失败统计
    success_count: int = 0
    failed_count: int = 0

    # GitHub API统计
    github_api_calls: int = 0
    github_api_failures: int = 0

    # GPT分析统计
    gpt_calls: int = 0
    gpt_failures: int = 0
    gpt_parsing_failures: int = 0

    # 克隆统计
    clone_count: int = 0
    clone_failures: int = 0

    # 更新检测统计
    update_check_count: int = 0
    update_detected_count: int = 0

    # 错误记录
    errors: List[Dict] = field(default_factory=list)

    # 临时文件清理统计
    temp_dirs_created: int = 0
    temp_dirs_cleaned: int = 0
    temp_cleanup_failures: int = 0


class Monitor:
    """监控和告警管理器"""

    def __init__(self):
        self.metrics = MonitorMetrics()
        self._error_counts = defaultdict(int)  # 按错误类型计数

    def record_cve_found(self, count: int = 1):
        """记录发现CVE数量"""
        self.metrics.total_cves += count

    def record_repo_found(self, count: int = 1):
        """记录发现仓库数量"""
        self.metrics.total_repos += count

    def record_repo_new(self):
        """记录新仓库"""
        self.metrics.new_repos += 1
        self.metrics.success_count += 1

    def record_repo_updated(self):
        """记录更新仓库"""
        self.metrics.updated_repos += 1
        self.metrics.success_count += 1

    def record_repo_skipped(self):
        """记录跳过仓库（无更新）"""
        self.metrics.skipped_repos += 1

    def record_repo_failed(self):
        """记录处理失败"""
        self.metrics.failed_count += 1

    def record_github_api_call(self, success: bool = True):
        """记录GitHub API调用"""
        self.metrics.github_api_calls += 1
        if not success:
            self.metrics.github_api_failures += 1

    def record_gpt_call(self, success: bool = True):
        """记录GPT调用"""
        self.metrics.gpt_calls += 1
        if not success:
            self.metrics.gpt_failures += 1

    def record_gpt_parsing_failure(self):
        """记录GPT解析失败"""
        self.metrics.gpt_parsing_failures += 1

    def record_clone(self, success: bool = True):
        """记录仓库克隆"""
        self.metrics.clone_count += 1
        if not success:
            self.metrics.clone_failures += 1

    def record_update_check(self, has_update: bool = False):
        """记录更新检测"""
        self.metrics.update_check_count += 1
        if has_update:
            self.metrics.update_detected_count += 1

    def record_temp_dir_created(self):
        """记录临时目录创建"""
        self.metrics.temp_dirs_created += 1

    def record_temp_dir_cleaned(self, success: bool = True):
        """记录临时目录清理"""
        if success:
            self.metrics.temp_dirs_cleaned += 1
        else:
            self.metrics.temp_cleanup_failures += 1

    def record_error(self, error_type: str, error_message: str, context: Optional[Dict] = None):
        """
        记录错误

        参数:
            error_type: 错误类型（如 'clone_failure', 'gpt_failure'）
            error_message: 错误信息
            context: 错误上下文（如仓库URL、CVE ID等）
        """
        error_record = {
            'timestamp': datetime.now().isoformat(),
            'type': error_type,
            'message': error_message,
            'context': context or {}
        }
        self.metrics.errors.append(error_record)
        self._error_counts[error_type] += 1

        # 记录到日志
        logger.error(f"[监控] {error_type}: {error_message} | 上下文: {context}")

    def get_runtime(self) -> float:
        """获取运行时间（秒）"""
        return time.time() - self.metrics.start_time

    def get_success_rate(self) -> float:
        """获取成功率（百分比）"""
        total = self.metrics.success_count + self.metrics.failed_count
        if total == 0:
            return 0.0
        return (self.metrics.success_count / total) * 100

    def get_github_api_success_rate(self) -> float:
        """获取GitHub API成功率"""
        if self.metrics.github_api_calls == 0:
            return 0.0
        success = self.metrics.github_api_calls - self.metrics.github_api_failures
        return (success / self.metrics.github_api_calls) * 100

    def get_gpt_success_rate(self) -> float:
        """获取GPT调用成功率"""
        if self.metrics.gpt_calls == 0:
            return 0.0
        success = self.metrics.gpt_calls - self.metrics.gpt_failures
        return (success / self.metrics.gpt_calls) * 100

    def get_clone_success_rate(self) -> float:
        """获取克隆成功率"""
        if self.metrics.clone_count == 0:
            return 0.0
        success = self.metrics.clone_count - self.metrics.clone_failures
        return (success / self.metrics.clone_count) * 100

    def get_temp_cleanup_rate(self) -> float:
        """获取临时文件清理成功率"""
        if self.metrics.temp_dirs_created == 0:
            return 100.0  # 未创建临时目录，默认100%
        return (self.metrics.temp_dirs_cleaned / self.metrics.temp_dirs_created) * 100

    def get_update_detection_rate(self) -> float:
        """获取更新检测命中率"""
        if self.metrics.update_check_count == 0:
            return 0.0
        return (self.metrics.update_detected_count / self.metrics.update_check_count) * 100

    def get_summary(self) -> Dict:
        """获取监控摘要"""
        runtime = self.get_runtime()

        summary = {
            'runtime': {
                'seconds': runtime,
                'formatted': f"{int(runtime // 60)}分{int(runtime % 60)}秒"
            },
            'discovery': {
                'total_cves': self.metrics.total_cves,
                'total_repos': self.metrics.total_repos
            },
            'processing': {
                'new': self.metrics.new_repos,
                'updated': self.metrics.updated_repos,
                'skipped': self.metrics.skipped_repos,
                'success': self.metrics.success_count,
                'failed': self.metrics.failed_count,
                'success_rate': f"{self.get_success_rate():.1f}%"
            },
            'github_api': {
                'calls': self.metrics.github_api_calls,
                'failures': self.metrics.github_api_failures,
                'success_rate': f"{self.get_github_api_success_rate():.1f}%"
            },
            'gpt': {
                'calls': self.metrics.gpt_calls,
                'failures': self.metrics.gpt_failures,
                'parsing_failures': self.metrics.gpt_parsing_failures,
                'success_rate': f"{self.get_gpt_success_rate():.1f}%"
            },
            'clone': {
                'count': self.metrics.clone_count,
                'failures': self.metrics.clone_failures,
                'success_rate': f"{self.get_clone_success_rate():.1f}%"
            },
            'update_check': {
                'total': self.metrics.update_check_count,
                'updates_found': self.metrics.update_detected_count,
                'detection_rate': f"{self.get_update_detection_rate():.1f}%"
            },
            'temp_cleanup': {
                'created': self.metrics.temp_dirs_created,
                'cleaned': self.metrics.temp_dirs_cleaned,
                'failures': self.metrics.temp_cleanup_failures,
                'cleanup_rate': f"{self.get_temp_cleanup_rate():.1f}%"
            },
            'errors': {
                'total': len(self.metrics.errors),
                'by_type': dict(self._error_counts),
                'recent': self.metrics.errors[-10:]  # 最近10个错误
            }
        }

        return summary

    def print_summary(self):
        """打印监控摘要到日志"""
        summary = self.get_summary()

        logger.info("=" * 60)
        logger.info("运行监控摘要")
        logger.info("=" * 60)

        logger.info(f"运行时长: {summary['runtime']['formatted']}")
        logger.info("")

        logger.info("发现统计:")
        logger.info(f"  CVE总数: {summary['discovery']['total_cves']}")
        logger.info(f"  仓库总数: {summary['discovery']['total_repos']}")
        logger.info("")

        logger.info("处理统计:")
        logger.info(f"  新仓库: {summary['processing']['new']}")
        logger.info(f"  更新仓库: {summary['processing']['updated']}")
        logger.info(f"  跳过（无更新）: {summary['processing']['skipped']}")
        logger.info(f"  成功: {summary['processing']['success']}")
        logger.info(f"  失败: {summary['processing']['failed']}")
        logger.info(f"  成功率: {summary['processing']['success_rate']}")
        logger.info("")

        logger.info("GitHub API统计:")
        logger.info(f"  调用次数: {summary['github_api']['calls']}")
        logger.info(f"  失败次数: {summary['github_api']['failures']}")
        logger.info(f"  成功率: {summary['github_api']['success_rate']}")
        logger.info("")

        if summary['gpt']['calls'] > 0:
            logger.info("GPT分析统计:")
            logger.info(f"  调用次数: {summary['gpt']['calls']}")
            logger.info(f"  失败次数: {summary['gpt']['failures']}")
            logger.info(f"  解析失败: {summary['gpt']['parsing_failures']}")
            logger.info(f"  成功率: {summary['gpt']['success_rate']}")
            logger.info("")

        if summary['clone']['count'] > 0:
            logger.info("克隆统计:")
            logger.info(f"  克隆次数: {summary['clone']['count']}")
            logger.info(f"  失败次数: {summary['clone']['failures']}")
            logger.info(f"  成功率: {summary['clone']['success_rate']}")
            logger.info("")

        if summary['update_check']['total'] > 0:
            logger.info("更新检测统计:")
            logger.info(f"  检测次数: {summary['update_check']['total']}")
            logger.info(f"  发现更新: {summary['update_check']['updates_found']}")
            logger.info(f"  更新率: {summary['update_check']['detection_rate']}")
            logger.info("")

        if summary['temp_cleanup']['created'] > 0:
            logger.info("临时文件清理:")
            logger.info(f"  创建: {summary['temp_cleanup']['created']}")
            logger.info(f"  清理: {summary['temp_cleanup']['cleaned']}")
            logger.info(f"  失败: {summary['temp_cleanup']['failures']}")
            logger.info(f"  清理率: {summary['temp_cleanup']['cleanup_rate']}")
            logger.info("")

        if summary['errors']['total'] > 0:
            logger.info("错误统计:")
            logger.info(f"  总错误数: {summary['errors']['total']}")
            logger.info(f"  按类型分布: {summary['errors']['by_type']}")
            logger.info("")

        logger.info("=" * 60)

    def save_to_file(self, filepath: str):
        """
        保存监控数据到文件

        参数:
            filepath: 保存路径（JSON格式）
        """
        summary = self.get_summary()

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
            logger.info(f"监控数据已保存到: {filepath}")
        except Exception as e:
            logger.error(f"保存监控数据失败: {e}")

    def check_health(self) -> Dict:
        """
        健康状态检查

        返回:
            健康状态字典，包含状态和警告信息
        """
        warnings = []
        status = 'healthy'

        # 检查成功率
        if self.metrics.success_count + self.metrics.failed_count > 0:
            success_rate = self.get_success_rate()
            if success_rate < 50:
                warnings.append(f"成功率过低: {success_rate:.1f}%")
                status = 'critical'
            elif success_rate < 80:
                warnings.append(f"成功率较低: {success_rate:.1f}%")
                if status == 'healthy':
                    status = 'warning'

        # 检查GitHub API失败率
        if self.metrics.github_api_calls > 0:
            api_success_rate = self.get_github_api_success_rate()
            if api_success_rate < 80:
                warnings.append(f"GitHub API成功率低: {api_success_rate:.1f}%")
                if status == 'healthy':
                    status = 'warning'

        # 检查临时文件清理
        if self.metrics.temp_cleanup_failures > 0:
            warnings.append(f"临时文件清理失败: {self.metrics.temp_cleanup_failures}次")
            if status == 'healthy':
                status = 'warning'

        # 检查错误数量
        if len(self.metrics.errors) > 10:
            warnings.append(f"错误数量较多: {len(self.metrics.errors)}个")
            if status == 'healthy':
                status = 'warning'

        return {
            'status': status,
            'warnings': warnings,
            'timestamp': datetime.now().isoformat()
        }


# 全局监控实例
_monitor_instance: Optional[Monitor] = None


def get_monitor() -> Monitor:
    """获取全局监控实例"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = Monitor()
    return _monitor_instance


def reset_monitor():
    """重置全局监控实例（用于测试）"""
    global _monitor_instance
    _monitor_instance = Monitor()

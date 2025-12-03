#!/usr/bin/env python3
"""
SearXNG 搜索引擎池管理
支持多引擎配置、故障转移、健康监控和权重调整
"""

import json
import logging
import os
import time
import requests
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from threading import Lock
from config import get_config

logger = logging.getLogger(__name__)


class SearchEngine:
    """单个搜索引擎实例"""

    def __init__(self, config: Dict):
        self.name = config.get('name', 'unknown')
        self.url = config.get('url', '').rstrip('/')
        self.priority = config.get('priority', 999)
        self.timeout = config.get('timeout', 15)
        self.ssl_verify = config.get('ssl_verify', True)
        self.enabled = config.get('enabled', True)
        self.weight = config.get('weight', 50)

        # 健康状态
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.total_requests = 0
        self.total_failures = 0
        self.last_success_time = None
        self.last_failure_time = None
        self.last_response_time = None

    def __repr__(self):
        status = "✓" if self.enabled else "✗"
        return f"<Engine {status} {self.name} w:{self.weight} f:{self.consecutive_failures}>"

    def record_success(self, response_time: float):
        """记录成功请求"""
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        self.total_requests += 1
        self.last_success_time = time.time()
        self.last_response_time = response_time

        # 成功后逐步恢复权重
        if self.weight < 100:
            self.weight = min(100, self.weight + 5)
            logger.debug(f"{self.name}: 权重恢复至 {self.weight}")

    def record_failure(self, error: str):
        """记录失败请求"""
        self.consecutive_successes = 0
        self.consecutive_failures += 1
        self.total_requests += 1
        self.total_failures += 1
        self.last_failure_time = time.time()

        # 失败后降低权重
        self.weight = max(0, self.weight - 10)
        logger.warning(f"{self.name}: 失败 ({error}), 权重降至 {self.weight}")

    def should_disable(self, threshold: int = 3) -> bool:
        """判断是否应该临时禁用"""
        return self.consecutive_failures >= threshold

    def should_enable(self, threshold: int = 2) -> bool:
        """判断是否应该重新启用"""
        return self.consecutive_successes >= threshold and not self.enabled

    def get_health_score(self) -> int:
        """计算健康分数 (0-100)"""
        if self.total_requests == 0:
            return self.weight

        success_rate = (self.total_requests - self.total_failures) / self.total_requests
        base_score = int(success_rate * 100)

        # 最近连续失败严重降分
        penalty = min(50, self.consecutive_failures * 15)

        return max(0, min(100, base_score - penalty))


class SearchEnginePool:
    """搜索引擎池管理器"""

    def __init__(self):
        self.engines: List[SearchEngine] = []
        self.lock = Lock()
        self._load_engines()

    def _load_engines(self):
        """加载搜索引擎配置 (优先级: 环境变量 > 默认配置)"""

        # 1. 尝试从环境变量加载用户配置
        env_urls = get_config('SEARXNG_URLS')
        if env_urls:
            logger.info("检测到环境变量 SEARXNG_URLS,加载用户配置")
            if self._load_from_env(env_urls):
                logger.info(f"✓ 成功加载 {len(self.engines)} 个用户配置引擎")
                return
            else:
                logger.warning("✗ 用户配置加载失败,降级到默认配置")

        # 2. 降级到默认配置文件
        logger.info("使用系统默认搜索引擎配置")
        if self._load_from_default():
            logger.info(f"✓ 成功加载 {len(self.engines)} 个默认引擎")
        else:
            logger.error("✗ 默认配置也加载失败,无可用搜索引擎!")

    def _load_from_env(self, urls_str: str) -> bool:
        """
        从环境变量加载引擎配置
        格式: http://host1:port1/search,http://host2:port2/search,...
        """
        try:
            # 按逗号分割URL列表
            urls = [url.strip() for url in urls_str.split(',') if url.strip()]

            if not urls:
                logger.error("SEARXNG_URLS 为空")
                return False

            logger.debug(f"解析到 {len(urls)} 个引擎URL")

            # 为每个URL创建引擎配置
            for idx, url in enumerate(urls, 1):
                # 提取域名/IP作为引擎名称
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    name = parsed.netloc or f"engine-{idx}"
                except:
                    name = f"engine-{idx}"

                # 判断是否HTTPS
                is_https = url.startswith('https://')

                config = {
                    'name': name,
                    'url': url.rstrip('/'),
                    'priority': idx,
                    'timeout': 15,
                    'ssl_verify': is_https,
                    'enabled': True,
                    'weight': 100 - (idx - 1) * 5,  # 权重递减
                }

                engine = SearchEngine(config)
                self.engines.append(engine)
                logger.debug(f"  [{idx}] {engine.name} - {engine.url}")

            return True

        except Exception as e:
            logger.error(f"解析环境变量失败: {e}")
            return False

    def _load_from_default(self) -> bool:
        """从默认配置文件加载引擎"""
        try:
            default_config_path = Path(__file__).parent / 'default_search_engines.json'

            if not default_config_path.exists():
                logger.error(f"默认配置文件不存在: {default_config_path}")
                return False

            with open(default_config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            engines_config = config_data.get('engines', [])

            if not engines_config:
                logger.error("默认配置中没有引擎定义")
                return False

            for engine_config in engines_config:
                engine = SearchEngine(engine_config)
                self.engines.append(engine)
                logger.debug(f"  加载默认引擎: {engine}")

            return True

        except Exception as e:
            logger.error(f"加载默认配置失败: {e}")
            return False

    def get_best_engine(self) -> Optional[SearchEngine]:
        """
        获取当前最佳引擎 (根据enabled状态、权重和优先级)
        """
        with self.lock:
            # 过滤出已启用的引擎
            available = [e for e in self.engines if e.enabled]

            if not available:
                logger.error("没有可用的搜索引擎!")
                return None

            # 按优先级排序,再按权重排序
            available.sort(key=lambda e: (-e.weight, e.priority))

            best = available[0]
            logger.debug(f"选择引擎: {best.name} (权重:{best.weight})")
            return best

    def get_all_engines(self) -> List[SearchEngine]:
        """获取所有引擎列表 (按优先级排序)"""
        with self.lock:
            return sorted(self.engines, key=lambda e: e.priority)

    def update_engine_status(self):
        """更新引擎启用/禁用状态 (基于失败次数)"""
        with self.lock:
            for engine in self.engines:
                # 连续失败超过阈值,临时禁用
                if engine.should_disable(threshold=3):
                    if engine.enabled:
                        logger.warning(f"引擎 {engine.name} 连续失败 {engine.consecutive_failures} 次,临时禁用")
                        engine.enabled = False

                # 连续成功达到阈值,重新启用
                elif engine.should_enable(threshold=2):
                    logger.info(f"引擎 {engine.name} 恢复正常,重新启用")
                    engine.enabled = True

    def search(self, query: str, max_results: int = 10) -> Tuple[Optional[Dict], Optional[SearchEngine]]:
        """
        执行搜索 (自动故障转移)

        返回:
            (搜索结果, 使用的引擎) 或 (None, None)
        """
        # 获取所有可用引擎,按优先级尝试
        available_engines = [e for e in self.get_all_engines() if e.enabled]

        if not available_engines:
            logger.error("没有可用的搜索引擎")
            return None, None

        for engine in available_engines:
            try:
                logger.info(f"尝试引擎: {engine.name} ({engine.url})")

                # 发送搜索请求
                start_time = time.time()

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json',
                }

                response = requests.get(
                    engine.url,
                    params={'q': query, 'format': 'json', 'max_results': max_results},
                    headers=headers,
                    timeout=engine.timeout,
                    verify=engine.ssl_verify
                )

                response_time = time.time() - start_time

                # 检查响应
                if response.status_code == 200:
                    try:
                        data = response.json()
                        results = data.get('results', [])

                        if results:
                            logger.info(f"✓ {engine.name} 返回 {len(results)} 条结果 ({response_time:.2f}s)")
                            engine.record_success(response_time)
                            self.update_engine_status()
                            return data, engine
                        else:
                            logger.warning(f"{engine.name} 返回0条结果")
                            engine.record_failure("空结果")
                    except json.JSONDecodeError as e:
                        logger.warning(f"{engine.name} JSON解析失败: {str(e)[:100]}")
                        engine.record_failure("JSON解析失败")
                else:
                    logger.warning(f"{engine.name} HTTP {response.status_code}")
                    engine.record_failure(f"HTTP {response.status_code}")

            except requests.exceptions.Timeout:
                logger.warning(f"{engine.name} 超时 (>{engine.timeout}s)")
                engine.record_failure("超时")
            except requests.exceptions.RequestException as e:
                logger.warning(f"{engine.name} 请求失败: {str(e)[:100]}")
                engine.record_failure("请求失败")
            except Exception as e:
                logger.error(f"{engine.name} 未知错误: {e}")
                engine.record_failure("未知错误")

            # 更新引擎状态
            self.update_engine_status()

        logger.error("所有搜索引擎均失败")
        return None, None

    def get_stats(self) -> Dict:
        """获取引擎池统计信息"""
        with self.lock:
            total = len(self.engines)
            enabled = sum(1 for e in self.engines if e.enabled)

            return {
                'total_engines': total,
                'enabled_engines': enabled,
                'disabled_engines': total - enabled,
                'engines': [
                    {
                        'name': e.name,
                        'url': e.url,
                        'enabled': e.enabled,
                        'weight': e.weight,
                        'health_score': e.get_health_score(),
                        'total_requests': e.total_requests,
                        'total_failures': e.total_failures,
                        'consecutive_failures': e.consecutive_failures,
                        'last_response_time': e.last_response_time,
                    }
                    for e in sorted(self.engines, key=lambda x: x.priority)
                ]
            }


# 全局单例
_engine_pool = None
_pool_lock = Lock()


def get_engine_pool() -> SearchEnginePool:
    """获取全局引擎池单例"""
    global _engine_pool

    if _engine_pool is None:
        with _pool_lock:
            if _engine_pool is None:
                logger.info("初始化搜索引擎池...")
                _engine_pool = SearchEnginePool()

    return _engine_pool


def search_with_engines(query: str, max_results: int = 10) -> Tuple[Optional[Dict], Optional[str]]:
    """
    使用引擎池执行搜索

    返回:
        (搜索结果dict, 使用的引擎名称) 或 (None, None)
    """
    pool = get_engine_pool()
    result, engine = pool.search(query, max_results)

    engine_name = engine.name if engine else None
    return result, engine_name


def get_engine_stats() -> Dict:
    """获取引擎池状态"""
    pool = get_engine_pool()
    return pool.get_stats()


if __name__ == '__main__':
    # 测试代码
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 80)
    print("SearXNG 引擎池测试")
    print("=" * 80)

    # 测试搜索
    result, engine = search_with_engines('CVE-2024-1234', max_results=5)

    if result:
        print(f"\n✓ 搜索成功,使用引擎: {engine}")
        print(f"  结果数: {len(result.get('results', []))}")
    else:
        print("\n✗ 搜索失败")

    # 显示统计
    print("\n" + "=" * 80)
    print("引擎池统计")
    print("=" * 80)
    stats = get_engine_stats()
    print(f"总引擎数: {stats['total_engines']}")
    print(f"启用: {stats['enabled_engines']}, 禁用: {stats['disabled_engines']}")
    print("\n引擎详情:")
    for e in stats['engines']:
        status = "✓" if e['enabled'] else "✗"
        print(f"  {status} {e['name']}")
        print(f"     URL: {e['url']}")
        print(f"     权重: {e['weight']}, 健康分: {e['health_score']}")
        print(f"     请求: {e['total_requests']}, 失败: {e['total_failures']}")

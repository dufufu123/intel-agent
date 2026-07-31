"""
IOC 白名单过滤 — 前置过滤明确良性资产

约束：在 LLM 判级之前过滤，降误报 + 省 token。
支持 YAML 配置（config/whitelist.yaml），可自定义。
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import List, Tuple

import yaml

# 默认配置文件路径
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "whitelist.yaml"


class WhitelistFilter:
    """白名单过滤器：滤掉云厂商/CDN/安全厂商域名与私有 IP 段"""

    def __init__(self, config_path: Path | None = None):
        """
        Args:
            config_path: whitelist.yaml 路径，默认 config/whitelist.yaml
        """
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._private_networks: list[ipaddress.IPv4Network] = []
        self._domain_suffixes: set[str] = set()
        self._exact_values: set[str] = set()
        self._load_config()

    def _load_config(self) -> None:
        """加载白名单配置"""
        if not self._config_path.exists():
            return

        with open(self._config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        # 私有 IP 段
        for cidr in config.get("private_ip_ranges", []):
            try:
                self._private_networks.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                pass

        # 域名后缀（合并 CDN/云/安全厂商/公共服务/示例域名）
        for section in [
            "cdn_and_cloud_domains",
            "security_vendor_domains",
            "public_service_domains",
            "example_domains",
        ]:
            for domain in config.get(section, []):
                self._domain_suffixes.add(domain.lower().strip())

        # 精确值（如公共 DNS IP）
        for domain in config.get("public_service_domains", []):
            # 尝试解析为 IP
            try:
                ipaddress.IPv4Address(domain)
                self._exact_values.add(domain.strip())
            except (ipaddress.AddressValueError, ValueError):
                pass

    def is_whitelisted(self, value: str, candidate_type: str) -> bool:
        """
        检查单个 IOC 是否在白名单中。

        Args:
            value: IOC 值
            candidate_type: 候选类型（Domain/IPv4 等）

        Returns:
            True 表示应过滤掉
        """
        value_lower = value.strip().lower()

        # 精确匹配
        if value_lower in self._exact_values:
            return True

        # IP 类：检查是否在私有/保留 IP 段
        if candidate_type in ("IPv4", "IPv6"):
            try:
                ip = ipaddress.IPv4Address(value.strip())
                for network in self._private_networks:
                    if ip in network:
                        return True
            except (ValueError, ipaddress.AddressValueError):
                pass
            return False

        # 域名类：检查后缀匹配
        if candidate_type in ("Domain", "URL"):
            for suffix in self._domain_suffixes:
                if value_lower == suffix or value_lower.endswith("." + suffix):
                    return True

        return False

    def filter_candidates(
        self, candidates: List[Tuple[str, str]]
    ) -> List[Tuple[str, str]]:
        """
        过滤 IOC 候选列表。

        Args:
            candidates: [(value, candidate_type), ...]

        Returns:
            过滤后的候选列表
        """
        return [
            (val, typ)
            for val, typ in candidates
            if not self.is_whitelisted(val, typ)
        ]

    def reload(self) -> None:
        """重新加载白名单配置"""
        self._private_networks.clear()
        self._domain_suffixes.clear()
        self._exact_values.clear()
        self._load_config()


# 全局单例
_whitelist: WhitelistFilter | None = None


def get_whitelist(config_path: Path | None = None) -> WhitelistFilter:
    """获取白名单过滤器单例"""
    global _whitelist
    if _whitelist is None:
        _whitelist = WhitelistFilter(config_path)
    return _whitelist


def filter_ioc_candidates(
    candidates: List[Tuple[str, str]],
    config_path: Path | None = None,
) -> List[Tuple[str, str]]:
    """
    过滤 IOC 候选（便捷函数）。

    Args:
        candidates: [(value, candidate_type), ...]
        config_path: 可选配置文件路径

    Returns:
        过滤后的候选列表
    """
    return get_whitelist(config_path).filter_candidates(candidates)
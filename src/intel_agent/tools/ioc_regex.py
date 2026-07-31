"""
IOC 正则提取 — 8 类正则模式从文本中召回 IOC 候选

约束：只召回不判级。返回 [(value, candidate_type), ...]。
正则管格式，LLM 管语义判级。
"""

from __future__ import annotations

import re
from typing import List, Tuple

# ============================================================
# 8 类 IOC 正则模式
# ============================================================

# 1. IPv4 地址
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# 2. IPv6 地址（完整格式）
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
)

# 3. 域名（含子域名，排除纯 IP）
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b'
)

# 4. URL（http/https/ftp）
URL_PATTERN = re.compile(
    r'\b(?:https?|ftp)://'
    r'[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*'
    r'(?::\d{1,5})?'
    r'(?:/[^\s\[\]\(\)\{\}"\'<>]*)?'
    r'\b'
)

# 5. 哈希值
HASH_MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# 6. 文件路径（Windows 和 Unix 风格）
FILE_PATH_PATTERN = re.compile(
    r'(?:[A-Za-z]:\\[\w\s\-\.\\]+|'
    r'/(?:[\w\-\.]+/)*[\w\-\.]+|'
    r'%[A-Za-z]+%\\[\w\s\-\.\\]+|'
    r'\\\\[\w\-\.]+\\[\w\s\-\.\\]+)'
)

# 7. 注册表项
REGISTRY_PATTERN = re.compile(
    r'\b(?:HK(?:LM|CU|CR|U|CC|PD|DD|EY)\\)[^\s\[\]\(\)\{\}"\'<>]*\b|'
    r'\bHKEY_[A-Z_]+\\[^\s\[\]\(\)\{\}"\'<>]*\b'
)

# 8. 邮箱地址
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)


# ============================================================
# 提取函数
# ============================================================

def extract_ipv4(text: str) -> List[Tuple[str, str]]:
    """提取 IPv4 地址"""
    return [(m.group(), "IPv4") for m in IPV4_PATTERN.finditer(text)]


def extract_ipv6(text: str) -> List[Tuple[str, str]]:
    """提取 IPv6 地址"""
    return [(m.group(), "IPv6") for m in IPV6_PATTERN.finditer(text)]


def extract_domain(text: str) -> List[Tuple[str, str]]:
    """提取域名"""
    return [(m.group().rstrip('.'), "Domain") for m in DOMAIN_PATTERN.finditer(text)]


def extract_url(text: str) -> List[Tuple[str, str]]:
    """提取 URL"""
    return [(m.group(), "URL") for m in URL_PATTERN.finditer(text)]


def extract_hash(text: str) -> List[Tuple[str, str]]:
    """提取各类哈希值（MD5/SHA1/SHA256）"""
    results: List[Tuple[str, str]] = []
    for m in HASH_MD5_PATTERN.finditer(text):
        results.append((m.group(), "MD5"))
    for m in HASH_SHA1_PATTERN.finditer(text):
        results.append((m.group(), "SHA1"))
    for m in HASH_SHA256_PATTERN.finditer(text):
        results.append((m.group(), "SHA256"))
    return results


def extract_file_path(text: str) -> List[Tuple[str, str]]:
    """提取文件路径"""
    return [(m.group(), "FilePath") for m in FILE_PATH_PATTERN.finditer(text)]


def extract_registry(text: str) -> List[Tuple[str, str]]:
    """提取注册表项"""
    return [(m.group(), "Registry") for m in REGISTRY_PATTERN.finditer(text)]


def extract_email(text: str) -> List[Tuple[str, str]]:
    """提取邮箱地址"""
    return [(m.group(), "Email") for m in EMAIL_PATTERN.finditer(text)]


# ============================================================
# 统一入口
# ============================================================

def extract_all_ioc_candidates(text: str) -> List[Tuple[str, str]]:
    """
    从文本中召回所有 IOC 候选。

    Args:
        text: 报告正文（纯文本）

    Returns:
        [(value, candidate_type), ...] 列表，按原文出现顺序排序
        其中 candidate_type ∈ {IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, FilePath, Registry, Email}
    """
    all_candidates: List[Tuple[str, str]] = []
    # 按类型依次提取，保留位置信息用于排序
    for extractor in [
        extract_ipv4,
        extract_ipv6,
        extract_domain,
        extract_url,
        extract_hash,
        extract_file_path,
        extract_registry,
        extract_email,
    ]:
        all_candidates.extend(extractor(text))

    # 按值去重，保持首次出现顺序
    seen: set = set()
    deduped: List[Tuple[str, str]] = []
    for val, typ in all_candidates:
        key = (val.strip().lower(), typ)
        if key not in seen:
            seen.add(key)
            deduped.append((val, typ))

    return deduped
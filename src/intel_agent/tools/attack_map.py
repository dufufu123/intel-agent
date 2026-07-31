"""
ATT&CK 映射表 — 技术名 -> 编号确定性查表

约束：确定性查表，LLM 只出技术名，代码查表转编号。
LLM 直出编号时校验是否已知；未知保留并标记。
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "attack_mapping.yaml"


class AttackMapping:
    """ATT&CK 技战术映射表"""

    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        # 技术名 -> 编号（模糊匹配用）
        self._name_to_id: Dict[str, str] = {}
        # 技术名 -> 战术
        self._name_to_tactic: Dict[str, str] = {}
        # 已知编号集合（用于校验 LLM 直出的编号）
        self._known_ids: set[str] = set()
        # 原始条目列表
        self._techniques: List[dict] = []
        self._load_config()

    def _load_config(self) -> None:
        if not self._config_path.exists():
            return

        with open(self._config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        self._techniques = config.get("techniques", [])
        self._name_to_id.clear()
        self._name_to_tactic.clear()
        self._known_ids.clear()

        for t in self._techniques:
            name = t["name"].strip().lower()
            tid = t["id"].strip()
            tactic = t.get("tactic", "").strip()

            self._name_to_id[name] = tid
            if tactic:
                self._name_to_tactic[name] = tactic
            self._known_ids.add(tid)

    def lookup_by_name(self, technique_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        按技术名查表。

        Args:
            technique_name: 技术名称（如 '鱼叉式钓鱼附件'）

        Returns:
            (technique_id, tactic) 或 (None, None) 表示未命中
        """
        key = technique_name.strip().lower()
        tid = self._name_to_id.get(key)
        tactic = self._name_to_tactic.get(key)
        return tid, tactic

    def is_known_id(self, technique_id: str) -> bool:
        """校验技术编号是否在已知表中"""
        return technique_id.strip() in self._known_ids

    def lookup_by_id(self, technique_id: str) -> Optional[dict]:
        """按编号查表，返回完整技术信息"""
        tid = technique_id.strip()
        for t in self._techniques:
            if t["id"].strip() == tid:
                return dict(t)
        return None

    def reload(self) -> None:
        self._load_config()

    @property
    def technique_count(self) -> int:
        return len(self._techniques)


# 全局单例
_attack_map: AttackMapping | None = None


def get_attack_map(config_path: Path | None = None) -> AttackMapping:
    global _attack_map
    if _attack_map is None:
        _attack_map = AttackMapping(config_path)
    return _attack_map


def map_technique_name(technique_name: str) -> Tuple[Optional[str], Optional[str]]:
    """便捷函数：技术名 -> (编号, 战术)"""
    return get_attack_map().lookup_by_name(technique_name)


def validate_technique_id(technique_id: str) -> bool:
    """便捷函数：校验技术编号是否已知"""
    return get_attack_map().is_known_id(technique_id)
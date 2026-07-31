"""
攻击者配置 + 热加载 — 匹配器 + 别名字典 + mtime 轮询

约束：配置匹配是纯 Python，LLM 只做确认/补漏/判型。
热加载不重启进程：基于 mtime 轮询检测变更。
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# 默认配置文件路径
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "actors.yaml"


class ActorConfig:
    """
    攻击者配置管理器

    功能：
    - 加载 actors.yaml，构建 {名称/别名 -> actor_info} 字典
    - 大小写不敏感、词边界匹配
    - 基于 mtime 轮询的热加载（可选 watchdog）
    """

    def __init__(
        self,
        config_path: Path | None = None,
        hot_reload: bool = True,
        reload_interval: float = 5.0,
    ):
        """
        Args:
            config_path: actors.yaml 路径
            hot_reload: 是否启用热加载
            reload_interval: 热加载轮询间隔（秒）
        """
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._hot_reload = hot_reload
        self._reload_interval = reload_interval

        self._alias_map: Dict[str, dict] = {}  # {别名.lower() -> actor_info}
        self._actors: List[dict] = []  # 原始列表
        self._last_mtime: float = 0.0
        self._lock = threading.RLock()

        self._load_config()
        if hot_reload:
            self._start_hot_reload_thread()

    # ---- 加载 ----

    def _load_config(self) -> None:
        """加载配置文件并构建别名字典"""
        if not self._config_path.exists():
            logger.warning("actors.yaml 不存在: %s", self._config_path)
            return

        with open(self._config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        with self._lock:
            self._actors = config.get("actors", [])
            self._alias_map = self._build_alias_dict(self._actors)
            self._last_mtime = self._config_path.stat().st_mtime

        logger.info(
            "加载 actors.yaml: %d 个组织, %d 个别名",
            len(self._actors),
            len(self._alias_map),
        )

    @staticmethod
    def _build_alias_dict(actors: List[dict]) -> Dict[str, dict]:
        """构建 {别名.lower() -> actor_info} 字典"""
        alias_map: Dict[str, dict] = {}
        for actor in actors:
            names = [actor["name"]] + actor.get("aliases", [])
            for alias in names:
                alias_map[alias.lower().strip()] = actor
        return alias_map

    # ---- 热加载 ----

    def _check_and_reload(self) -> bool:
        """检查 mtime 是否变更，如有则重新加载。返回 True 表示已重载"""
        try:
            current_mtime = self._config_path.stat().st_mtime
        except OSError:
            return False

        if current_mtime > self._last_mtime:
            logger.info("检测到 actors.yaml 变更，热加载中...")
            self._load_config()
            return True
        return False

    def _start_hot_reload_thread(self) -> None:
        """启动后台热加载线程"""
        def _poll():
            while True:
                time.sleep(self._reload_interval)
                try:
                    self._check_and_reload()
                except Exception:
                    logger.exception("热加载轮询异常")

        t = threading.Thread(target=_poll, daemon=True, name="actor-config-hot-reload")
        t.start()

    # ---- 匹配 ----

    def match_in_text(self, text: str) -> List[dict]:
        """
        在文本中匹配攻击者（词边界、大小写不敏感）。

        Args:
            text: 报告正文（纯文本）

        Returns:
            匹配到的 actor 信息列表，包含 id/name/theme/aliases
        """
        text_lower = text.lower()
        matched: Dict[str, dict] = {}

        with self._lock:
            for alias, info in self._alias_map.items():
                # 词边界匹配：确保不是更长字符串的子串
                if re.search(r'\b' + re.escape(alias) + r'\b', text_lower):
                    actor_id = info["id"]
                    if actor_id not in matched:
                        matched[actor_id] = dict(info)  # 浅拷贝

        return list(matched.values())

    def get_actor_names(self) -> List[str]:
        """获取所有已知攻击者名称列表"""
        with self._lock:
            return [a["name"] for a in self._actors]

    def get_actor_by_id(self, actor_id: str) -> Optional[dict]:
        """按 ID 获取攻击者信息"""
        with self._lock:
            for a in self._actors:
                if a["id"] == actor_id:
                    return dict(a)
        return None

    def is_known_actor(self, name: str) -> bool:
        """检查攻击者名称是否在配置中"""
        with self._lock:
            return name.lower().strip() in self._alias_map

    def lookup_by_name(self, name: str) -> Optional[dict]:
        """
        按名称或别名查找攻击者配置。

        Args:
            name: 攻击者名称或别名

        Returns:
            匹配到的 actor 信息 dict，或 None
        """
        with self._lock:
            return self._alias_map.get(name.lower().strip())

    def reload(self) -> None:
        """强制重新加载配置"""
        self._load_config()

    @property
    def actor_count(self) -> int:
        with self._lock:
            return len(self._actors)

    @property
    def alias_count(self) -> int:
        with self._lock:
            return len(self._alias_map)


# 全局单例
_actor_config: ActorConfig | None = None


def get_actor_config(
    config_path: Path | None = None,
    hot_reload: bool = True,
) -> ActorConfig:
    """获取攻击者配置管理器单例"""
    global _actor_config
    if _actor_config is None:
        _actor_config = ActorConfig(config_path=config_path, hot_reload=hot_reload)
    return _actor_config


def match_actors_in_text(text: str) -> List[dict]:
    """
    在文本中匹配攻击者（便捷函数）。

    Args:
        text: 报告正文

    Returns:
        匹配到的 actor 信息列表
    """
    return get_actor_config().match_in_text(text)
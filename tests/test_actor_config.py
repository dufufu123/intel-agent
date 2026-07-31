"""测试攻击者配置匹配"""
import tempfile
from pathlib import Path

import yaml

from intel_agent.tools.actor_config import ActorConfig


SAMPLE_CONFIG = {
    "version": 1,
    "actors": [
        {
            "id": "apt28",
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm"],
            "theme": "APT",
        },
        {
            "id": "conti",
            "name": "Conti",
            "aliases": ["Conti ransomware"],
            "theme": "恶意代码家族",
        },
    ],
}


class TestActorConfig:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        yaml.dump(SAMPLE_CONFIG, self.tmp, allow_unicode=True)
        self.tmp.close()
        self.config = ActorConfig(
            config_path=Path(self.tmp.name), hot_reload=False
        )

    def teardown_method(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_match_exact_name(self):
        results = self.config.match_in_text("APT28 组织发动了攻击")
        assert len(results) == 1
        assert results[0]["id"] == "apt28"

    def test_match_alias(self):
        results = self.config.match_in_text("Fancy Bear 使用了新工具")
        assert len(results) == 1
        assert results[0]["id"] == "apt28"

    def test_match_case_insensitive(self):
        results = self.config.match_in_text("conti 和 apt28 联合行动")
        assert len(results) == 2

    def test_match_word_boundary(self):
        # "Conti" 不应该匹配 "Continent"
        results = self.config.match_in_text("The Continent is large")
        assert len(results) == 0

    def test_no_match(self):
        results = self.config.match_in_text("没有已知攻击者")
        assert len(results) == 0

    def test_is_known_actor(self):
        assert self.config.is_known_actor("APT28")
        assert self.config.is_known_actor("fancy bear")
        assert not self.config.is_known_actor("UnknownActor")

    def test_get_actor_names(self):
        names = self.config.get_actor_names()
        assert "APT28" in names
        assert "Conti" in names

    def test_get_actor_by_id(self):
        actor = self.config.get_actor_by_id("apt28")
        assert actor is not None
        assert actor["name"] == "APT28"
        assert actor["theme"] == "APT"

    def test_reload(self):
        # 修改配置文件
        new_config = dict(SAMPLE_CONFIG)
        new_config["actors"].append({
            "id": "new_actor",
            "name": "NewActor",
            "aliases": [],
            "theme": "未知",
        })
        with open(self.tmp.name, "w", encoding="utf-8") as f:
            yaml.dump(new_config, f, allow_unicode=True)

        self.config.reload()
        assert self.config.is_known_actor("NewActor")
        assert self.config.actor_count == 3
"""测试 ATT&CK 映射表"""
import tempfile
from pathlib import Path

import yaml

from intel_agent.tools.attack_map import AttackMapping


SAMPLE_MAPPING = {
    "version": 1,
    "techniques": [
        {"name": "鱼叉式钓鱼附件", "id": "T1566.001", "tactic": "初始访问"},
        {"name": "PowerShell", "id": "T1059.001", "tactic": "执行"},
        {"name": "进程注入", "id": "T1055", "tactic": "防御规避"},
    ],
}


class TestAttackMapping:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        yaml.dump(SAMPLE_MAPPING, self.tmp, allow_unicode=True)
        self.tmp.close()
        self.mapping = AttackMapping(config_path=Path(self.tmp.name))

    def teardown_method(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_lookup_by_name_exact(self):
        tid, tactic = self.mapping.lookup_by_name("鱼叉式钓鱼附件")
        assert tid == "T1566.001"
        assert tactic == "初始访问"

    def test_lookup_by_name_case_insensitive(self):
        tid, tactic = self.mapping.lookup_by_name("powershell")
        assert tid == "T1059.001"

    def test_lookup_by_name_not_found(self):
        tid, tactic = self.mapping.lookup_by_name("不存在的技术")
        assert tid is None

    def test_is_known_id(self):
        assert self.mapping.is_known_id("T1566.001")
        assert self.mapping.is_known_id("T1055")
        assert not self.mapping.is_known_id("T9999")

    def test_lookup_by_id(self):
        result = self.mapping.lookup_by_id("T1055")
        assert result is not None
        assert result["name"] == "进程注入"
        assert result["tactic"] == "防御规避"

    def test_lookup_by_id_not_found(self):
        result = self.mapping.lookup_by_id("T9999")
        assert result is None

    def test_technique_count(self):
        assert self.mapping.technique_count == 3
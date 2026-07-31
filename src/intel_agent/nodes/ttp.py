"""
ATT&CK 映射节点 — LLM 输出技术名 -> 查表转编号

约束：
- 查表确定性，LLM 只出技术名
- LLM 直出 ID 时校验已知；未知保留并标记
"""

from __future__ import annotations

import logging
from typing import List

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import TTP_PROMPT
from ..tools.attack_map import get_attack_map

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型 ----

class TTPExtracted(BaseModel):
    """LLM 提取的 TTP 技术名"""
    technique_name: str = Field(description="ATT&CK 技术名称")
    description: str | None = Field(description="技术描述")


class TTPExtractionResult(BaseModel):
    """LLM TTP 提取结果"""
    ttps: list[TTPExtracted] = Field(description="提取的 TTP 列表")


def map_ttps_for_report(report_text: str) -> List[dict]:
    """
    从报告中提取 TTP 技术名，查表转编号。

    Args:
        report_text: 报告正文

    Returns:
        TTP 字典列表 [{"technique_id", "technique_name", "tactic", "description", "is_verified"}, ...]
    """
    logger.info("[map_ttps] 开始提取 TTP...")

    if not is_llm_available():
        logger.warning("[map_ttps] LLM 不可用，降级：返回空列表")
        return []

    attack_map = get_attack_map()

    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(TTPExtractionResult)
        result = extractor.invoke({"report_text": report_text[:12000]})

        if result is None:
            raise RuntimeError("LLM 返回 None")

        ttps = []
        for ttp in result.ttps:
            name = ttp.technique_name.strip()
            # 查表
            tid, tactic = attack_map.lookup_by_name(name)

            is_verified = True
            if tid is None:
                # 尝试直接匹配编号（LLM 可能直出编号）
                if attack_map.is_known_id(name):
                    tid = name
                    tactic = None
                else:
                    is_verified = False
                    logger.info("[map_ttps] 未知技术: %s", name)

            ttps.append({
                "technique_id": tid,
                "technique_name": name,
                "tactic": tactic,
                "description": ttp.description,
                "is_verified": is_verified,
            })

        logger.info("[map_ttps] 提取 %d 个 TTP（%d 个已验证）", len(ttps), sum(1 for t in ttps if t["is_verified"]))
        return ttps

    except Exception as e:
        logger.error("[map_ttps] 失败: %s", e)
        return []


def map_ttps_node(state: dict) -> dict:
    """
    ATT&CK 映射节点（LangGraph 节点函数）。

    在 fan-out 所有 actor 详情抽取完成后执行，为整个报告查 TTP 表。
    """
    report_text = state.get("report_text", "")
    ttps = map_ttps_for_report(report_text)

    return {
        "ttps": ttps,
        "execution_log": [f"map_ttps: 提取 {len(ttps)} 个 TTP"],
    }
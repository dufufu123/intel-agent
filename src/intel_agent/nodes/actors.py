"""
攻击者识别节点 — 配置匹配候选 -> LLM 确认 + 判 theme + 补漏 -> 标新组织

约束：
- 配置匹配是纯 Python，LLM 只做确认/补漏/判型
- 新组织标记逻辑必须实现（需求 2.3）
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import ACTOR_CONFIRM_PROMPT
from ..tools.actor_config import get_actor_config, match_actors_in_text

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型（仅用于本节点的结构化输出） ----

class ConfirmedActor(BaseModel):
    """LLM 确认/补漏的攻击者"""
    actor_id: str = Field(description="攻击者唯一标识")
    name: str = Field(description="攻击者名称")
    theme: str = Field(description="攻击者类型：APT/经济动机/黑客行动主义/恶意代码家族/勒索软件团伙/内部威胁/未知")
    is_confirmed: bool = Field(description="是否确认为本报告的攻击主体")
    is_new_org: bool = Field(description="是否为新组织（不在候选列表中）")
    aliases_matched: list[str] = Field(default_factory=list, description="在正文中匹配到的别名")


class ActorConfirmationResult(BaseModel):
    """LLM 攻击者确认结果"""
    confirmed_actors: list[ConfirmedActor] = Field(description="确认/补漏的攻击者列表")


def identify_actors_node(state: dict) -> dict:
    """
    识别攻击者（LangGraph 节点函数）。

    流程：
    1. 配置匹配（纯 Python）-> 候选列表
    2. LLM 确认候选是否为主体 + 判 theme + 补漏
    3. 不在配置中的标 new_org_flags
    """
    report_text = state.get("report_text", "")
    logger.info("[identify_actors] 开始识别攻击者...")

    # ---- 第一步：配置匹配 ----
    actor_config = get_actor_config()
    candidates = match_actors_in_text(report_text)
    logger.info(
        "[identify_actors] 配置匹配到 %d 个候选: %s",
        len(candidates),
        [c["name"] for c in candidates],
    )

    candidate_names = [c["name"] for c in candidates]
    candidate_ids = {c["id"] for c in candidates}

    # ---- 第二步：LLM 确认 + 补漏 ----
    if not is_llm_available():
        logger.warning("[identify_actors] LLM 不可用，降级：仅使用配置匹配结果")
        # 降级：所有候选默认确认
        actors = [
            {
                "actor_id": c["id"],
                "name": c["name"],
                "theme": c.get("theme", "未知"),
                "aliases_matched": [c["name"]],
                "is_new_org": False,
                "new_org_notice": None,
                "iocs": [],
                "tools": [],
                "vulnerabilities": [],
                "ttps": [],
            }
            for c in candidates
        ]
        return {
            "actors": actors,
            "new_org_flags": [],
            "execution_log": [f"identify_actors: 降级，配置匹配 {len(actors)} 个"],
        }

    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(ActorConfirmationResult)
        result = extractor.invoke({
            "candidates": ", ".join(candidate_names) if candidate_names else "（无候选，请从报告中直接识别）",
            "report_text": report_text[:8000],  # 截断，攻击者信息通常在报告前半部分
        })

        if result is None:
            raise RuntimeError("LLM 返回 None")

        confirmed = result.confirmed_actors
        logger.info("[identify_actors] LLM 确认 %d 个攻击者", len(confirmed))

    except Exception as e:
        logger.error("[identify_actors] LLM 确认失败: %s，降级：使用配置匹配", e)
        # 降级：所有候选默认确认
        confirmed = [
            ConfirmedActor(
                actor_id=c["id"],
                name=c["name"],
                theme=c.get("theme", "未知"),
                is_confirmed=True,
                is_new_org=False,
                aliases_matched=[c["name"]],
            )
            for c in candidates
        ]

    # ---- 第三步：构建 actor 列表 + 新组织标记 ----
    actors = []
    new_org_flags = []

    for ca in confirmed:
        if not ca.is_confirmed:
            continue

        is_new = ca.is_new_org or (ca.actor_id not in candidate_ids and ca.name not in candidate_names)

        new_org_notice = None
        if is_new:
            notice = f"{ca.name} 可能是新组织，建议核实后更新攻击组织档案库"
            new_org_flags.append(notice)
            new_org_notice = notice
            logger.info("[identify_actors] 新组织标记: %s", ca.name)

        actors.append({
            "actor_id": ca.actor_id,
            "name": ca.name,
            "theme": ca.theme if ca.theme else "未知",
            "aliases_matched": ca.aliases_matched,
            "is_new_org": is_new,
            "new_org_notice": new_org_notice,
            "iocs": [],
            "tools": [],
            "vulnerabilities": [],
            "ttps": [],
        })

    logger.info("[identify_actors] 最终确认 %d 个攻击者（%d 个新组织）", len(actors), len(new_org_flags))
    return {
        "actors": actors,
        "new_org_flags": new_org_flags,
        "execution_log": [f"identify_actors: 确认 {len(actors)} 个攻击者"],
    }
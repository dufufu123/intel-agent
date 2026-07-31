"""
IOC 抽取节点（fan-out 内，单 actor）— 仅抽取 IOC

此节点在 fan-out 并行中执行，每个 actor 一个实例。
tools/vulnerabilities/ttps 已在 identify_actors 节点由 LLM 完整抽取，此处透传。
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import ACTOR_DETAIL_PROMPT

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型 ----

class DetailIOC(BaseModel):
    value: str = Field(description="IOC 值")
    type: str = Field(description="IOC 类型：IP/Domain/Email/URL/Hash/CVE/TTP")
    threat_level: str = Field(description="威胁等级：恶意/可疑/未知/白名单", default="未知")
    tags: list[str] = Field(default_factory=list)
    context: str | None = Field(default=None)


class ActorDetailResult(BaseModel):
    """单 actor IOC 抽取结果"""
    iocs: list[DetailIOC] = Field(default_factory=list)


def extract_details_node(state: dict) -> dict:
    """
    对单个 actor 抽取 IOC（LangGraph 节点函数，fan-out 并行执行）。

    从 state["_current_actor"] 获取当前 actor 信息（含 tools/vulns/ttps），
    仅通过 LLM 抽取 IOC，其余字段透传。
    """
    actor = state.get("_current_actor", {})
    actor_name = actor.get("name", "unknown")
    actor_id = actor.get("actor_id", actor_name.lower().replace(" ", "-"))
    report_text = state.get("report_text", "")

    logger.info("[extract_details] LLM 抽取 %s 的 IOC...", actor_name)

    # 基础 actor 信息 + 透传 tools/vulns/ttps
    detail = {
        "actor_id": actor_id,
        "name": actor_name,
        "theme": actor.get("theme", "未知"),
        "aliases_matched": actor.get("aliases_matched", []),
        "is_new_org": actor.get("is_new_org", False),
        "new_org_notice": actor.get("new_org_notice"),
        "iocs": [],
        "tools": actor.get("tools", []),           # ← 透传自 identify_actors
        "vulnerabilities": actor.get("vulnerabilities", []),  # ← 透传
        "ttps": actor.get("ttps", []),             # ← 透传
    }

    if not is_llm_available():
        logger.warning("[extract_details] LLM 不可用，降级：%s 返回空 IOC", actor_name)
        return {
            "actor_details": [detail],
            "errors": [f"extract_details({actor_name}): LLM 不可用，降级"],
        }

    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(ActorDetailResult)
        messages = ACTOR_DETAIL_PROMPT.format_messages(
            report_text=report_text[:12000],
            actor_name=actor_name,
        )
        result = extractor.invoke(messages)

        if result is None:
            raise RuntimeError("LLM 返回 None")

        # 转换 IOC
        for ioc in result.iocs:
            detail["iocs"].append({
                "value": ioc.value,
                "type": ioc.type,
                "threat_level": ioc.threat_level or "未知",
                "tags": ioc.tags,
                "context": ioc.context,
            })

        logger.info("[extract_details] %s: %d IOC", actor_name, len(detail["iocs"]))

    except Exception as e:
        logger.error("[extract_details] %s 失败: %s", actor_name, e)
        return {
            "actor_details": [detail],
            "errors": [f"extract_details({actor_name}) 失败: {e}"],
        }

    return {
        "actor_details": [detail],
        "execution_log": [f"extract_details({actor_name}): {len(detail['iocs'])} IOC"],
    }
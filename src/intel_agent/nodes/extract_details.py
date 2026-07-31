"""
详情抽取节点（fan-out 内，单 actor）— IOC + 工具 + 漏洞 + TTP

此节点在 fan-out 并行中执行，每个 actor 一个实例。
合并 IOC 抽取、工具/漏洞/TTP 抽取。
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import ACTOR_DETAIL_PROMPT
from ..tools.actor_config import get_actor_config

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型 ----

class DetailIOC(BaseModel):
    value: str = Field(description="IOC 值")
    type: str = Field(description="IOC 类型")
    threat_level: str = Field(description="威胁等级", default="未知")
    tags: list[str] = Field(default_factory=list)
    context: str | None = Field(default=None)


class DetailTool(BaseModel):
    name: str = Field(description="工具/恶意软件名称")
    category: str | None = Field(default=None, description="分类")
    description: str | None = Field(default=None)


class DetailVuln(BaseModel):
    cve_id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    description: str | None = Field(default=None)


class DetailTTP(BaseModel):
    technique_name: str = Field(description="技术名称")
    description: str | None = Field(default=None)


class ActorDetailResult(BaseModel):
    """单 actor 详情抽取结果"""
    iocs: list[DetailIOC] = Field(default_factory=list)
    tools: list[DetailTool] = Field(default_factory=list)
    vulnerabilities: list[DetailVuln] = Field(default_factory=list)
    ttps: list[DetailTTP] = Field(default_factory=list)


def extract_details_node(state: dict) -> dict:
    """
    对单个 actor 抽取详情（LangGraph 节点函数，fan-out 并行执行）。

    从 state["_current_actor"] 获取当前 actor 信息，
    返回 actor_details 供 reducer 归并。
    """
    actor = state.get("_current_actor", {})
    actor_name = actor.get("name", "unknown")
    actor_id = actor.get("actor_id", actor_name.lower().replace(" ", "-"))
    report_text = state.get("report_text", "")

    logger.info("[extract_details] LLM 抽取 %s 的详情...", actor_name)

    # 基础 actor 信息
    detail = {
        "actor_id": actor_id,
        "name": actor_name,
        "theme": actor.get("theme", "未知"),
        "aliases_matched": actor.get("aliases_matched", []),
        "is_new_org": actor.get("is_new_org", False),
        "new_org_notice": actor.get("new_org_notice"),
        "iocs": [],
        "tools": [],
        "vulnerabilities": [],
        "ttps": [],
    }

    if not is_llm_available():
        logger.warning("[extract_details] LLM 不可用，降级：%s 返回空详情", actor_name)
        return {
            "actor_details": [detail],
            "errors": [f"extract_details({actor_name}): LLM 不可用，降级"],
        }

    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(ActorDetailResult)
        result = extractor.invoke({
            "report_text": report_text[:12000],
            "actor_name": actor_name,
        })

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

        # 转换工具
        for tool in result.tools:
            detail["tools"].append({
                "name": tool.name,
                "category": tool.category,
                "description": tool.description,
            })

        # 转换漏洞
        for vuln in result.vulnerabilities:
            detail["vulnerabilities"].append({
                "cve_id": vuln.cve_id,
                "name": vuln.name,
                "description": vuln.description,
            })

        # 转换 TTP（技术名，后续 map_ttps 节点查表）
        for ttp in result.ttps:
            detail["ttps"].append({
                "technique_name": ttp.technique_name,
                "technique_id": None,
                "tactic": None,
                "description": ttp.description,
                "is_verified": False,
            })

        logger.info(
            "[extract_details] %s: %d IOC, %d tools, %d vulns, %d TTPs",
            actor_name,
            len(detail["iocs"]),
            len(detail["tools"]),
            len(detail["vulnerabilities"]),
            len(detail["ttps"]),
        )

    except Exception as e:
        logger.error("[extract_details] %s 失败: %s", actor_name, e)
        return {
            "actor_details": [detail],
            "errors": [f"extract_details({actor_name}) 失败: {e}"],
        }

    return {
        "actor_details": [detail],
        "execution_log": [
            f"extract_details({actor_name}): {len(detail['iocs'])} IOC, "
            f"{len(detail['tools'])} tools, {len(detail['ttps'])} TTPs"
        ],
    }
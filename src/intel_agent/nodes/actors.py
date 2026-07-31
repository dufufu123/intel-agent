"""
攻击者识别节点 — LLM 直接从报告中识别攻击者 + 抽 tools/vulns/ttps -> 配置交叉比对 -> 标新组织

约束：
- LLM 直接识别所有攻击者，不依赖配置候选列表
- 配置仅用于交叉比对：补 actor_id、判断是否已知组织
- 新组织标记逻辑：不在配置中的标记 is_new_org
- tools/vulns/ttps 在此节点一次性由 LLM 完整抽取，后续 fan-out 只做 IOC
"""

from __future__ import annotations

import logging
import re

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import ACTOR_CONFIRM_PROMPT
from ..tools.actor_config import get_actor_config, match_actors_in_text

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型（仅用于本节点的结构化输出） ----

class ConfirmedTTP(BaseModel):
    """LLM 提取的 ATT&CK 技战术（含完整编号/名称/战术）"""
    technique_id: str = Field(description="ATT&CK 技术编号，如 T1566.001")
    technique_name: str = Field(description="技术名称，如 鱼叉式钓鱼附件")
    tactic: str = Field(description="所属战术，如 初始访问")
    description: str | None = Field(default=None, description="该技术在报告中的具体表现")


class ConfirmedTool(BaseModel):
    """LLM 提取的工具/恶意软件"""
    name: str = Field(description="工具/恶意软件名称")
    category: str | None = Field(default=None, description="分类：RAT/Downloader/Dropper/Exploit Kit/后门/勒索软件/正常工具")
    description: str | None = Field(default=None)


class ConfirmedVuln(BaseModel):
    """LLM 提取的漏洞"""
    cve_id: str | None = Field(default=None, description="CVE 编号，如 CVE-2021-34527")
    name: str | None = Field(default=None, description="漏洞名称，如 PrintNightmare")


class ConfirmedActor(BaseModel):
    """LLM 从报告中识别到的攻击者（仅含 LLM 能提供的信息，actor_id/is_new_org 由代码补全）"""
    name: str = Field(description="攻击者名称")
    theme: str = Field(description="攻击者类型：APT/恶意代码家族/未知")
    tools: list[ConfirmedTool] = Field(default_factory=list, description="该攻击者使用的工具/恶意软件")
    vulnerabilities: list[ConfirmedVuln] = Field(default_factory=list, description="该攻击者利用的漏洞")
    ttps: list[ConfirmedTTP] = Field(default_factory=list, description="该攻击者使用的 ATT&CK 技战术")


class ActorConfirmationResult(BaseModel):
    """LLM 攻击者识别结果"""
    confirmed_actors: list[ConfirmedActor] = Field(description="从报告中识别到的攻击者列表")


# ---- 配置交叉比对 ----

def _slugify(name: str) -> str:
    """将攻击者名称转为 actor_id 格式"""
    name = name.lower().strip()
    name = re.sub(r'[^\w\s\-]', '', name)
    name = re.sub(r'[\s]+', '-', name)
    return name


def _cross_reference_with_config(
    llm_actors: list[ConfirmedActor],
    actor_config,
) -> list[dict]:
    """
    将 LLM 识别到的攻击者与配置交叉比对。

    对每个 LLM 识别到的 actor：
    - 如果名称/别名命中配置：使用配置中的 actor_id 和 theme
    - 如果未命中：生成 actor_id，标记 is_new_org=True
    """
    actors = []

    for ca in llm_actors:
        name = ca.name.strip()
        config_actor = actor_config.lookup_by_name(name)

        if config_actor:
            # 命中配置：使用配置中的 ID 和 theme
            actor_id = config_actor["id"]
            theme = config_actor.get("theme", ca.theme) or ca.theme
            is_new = False
            new_org_notice = None
            aliases_matched = [name]
            logger.info("[identify_actors] %s → 命中配置 %s", name, actor_id)
        else:
            # 未命中：标记为新组织
            actor_id = _slugify(name)
            theme = ca.theme if ca.theme else "未知"
            is_new = True
            new_org_notice = f"{name} 可能是新组织，建议核实后更新攻击组织档案库"
            aliases_matched = []
            logger.info("[identify_actors] %s → 未命中配置，标记为新组织", name)

        actors.append({
            "actor_id": actor_id,
            "name": name,
            "theme": theme,
            "aliases_matched": aliases_matched,
            "is_new_org": is_new,
            "new_org_notice": new_org_notice,
            "iocs": [],
            "tools": [t.model_dump() for t in ca.tools] if ca.tools else [],
            "vulnerabilities": [v.model_dump() for v in ca.vulnerabilities] if ca.vulnerabilities else [],
            "ttps": [t.model_dump() for t in ca.ttps] if ca.ttps else [],
        })

    return actors


# ---- 节点函数 ----

def identify_actors_node(state: dict) -> dict:
    """
    识别攻击者（LangGraph 节点函数）。

    流程：
    1. LLM 直接从报告中识别所有攻击者 + 抽 tools/vulns/ttps
    2. 代码与配置交叉比对：补 actor_id、判断是否新组织
    3. LLM 不可用时降级为纯配置匹配
    """
    report_text = state.get("report_text", "")
    logger.info("[identify_actors] 开始识别攻击者...")

    actor_config = get_actor_config()

    # ---- LLM 不可用：降级为纯配置匹配 ----
    if not is_llm_available():
        logger.warning("[identify_actors] LLM 不可用，降级：仅使用配置匹配结果")
        candidates = match_actors_in_text(report_text)
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

    # ---- 第一步：LLM 直接从报告中识别攻击者 ----
    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(ActorConfirmationResult, prompt=ACTOR_CONFIRM_PROMPT)
        result = extractor.invoke({"report_text": report_text})

        if result is None:
            raise RuntimeError("LLM 返回 None")

        llm_actors = result.confirmed_actors
        logger.info("[identify_actors] LLM 识别到 %d 个攻击者: %s",
                     len(llm_actors), [a.name for a in llm_actors])

    except Exception as e:
        logger.error("[identify_actors] LLM 识别失败: %s，降级：使用配置匹配", e)
        candidates = match_actors_in_text(report_text)
        confirmed = [
            ConfirmedActor(
                name=c["name"],
                theme=c.get("theme", "未知"),
            )
            for c in candidates
        ]
        llm_actors = confirmed

    # ---- 第二步：配置交叉比对 ----
    actors = _cross_reference_with_config(llm_actors, actor_config)

    new_org_flags = [
        a["new_org_notice"]
        for a in actors
        if a["is_new_org"] and a["new_org_notice"]
    ]

    logger.info("[identify_actors] 最终确认 %d 个攻击者（%d 个新组织）", len(actors), len(new_org_flags))
    return {
        "actors": actors,
        "new_org_flags": new_org_flags,
        "execution_log": [f"identify_actors: 确认 {len(actors)} 个攻击者"],
    }
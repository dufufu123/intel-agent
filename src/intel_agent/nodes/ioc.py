"""
IOC 抽取节点（fan-out 内，单 actor）— 正则候选 -> 白名单过滤 -> LLM 判级

约束：
- 正则只召回不判级
- threat_level 必填，缺省"未知"
- 白名单在前省 LLM
"""

from __future__ import annotations

import logging
from typing import List

from pydantic import BaseModel, Field

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import IOC_CLASSIFY_PROMPT
from ..tools.ioc_regex import extract_all_ioc_candidates
from ..tools.whitelist import filter_ioc_candidates

logger = logging.getLogger(__name__)


# ---- 内部 Pydantic 模型 ----

class IOCClassified(BaseModel):
    """LLM 判级后的 IOC"""
    value: str = Field(description="IOC 值")
    type: str = Field(description="IOC 类型：IPv4/IPv6/Domain/URL/MD5/SHA1/SHA256/FilePath/Registry/Email")
    threat_level: str = Field(description="威胁等级：恶意/可疑/未知/白名单")
    tags: list[str] = Field(default_factory=list, description="附加标签")
    context: str | None = Field(default=None, description="上下文说明")


class IOCClassificationResult(BaseModel):
    """LLM IOC 判级结果"""
    iocs: list[IOCClassified] = Field(description="判级后的 IOC 列表")


def extract_ioc_for_actor(report_text: str, actor_name: str) -> List[dict]:
    """
    对单个 actor 抽取 IOC：正则候选 -> 白名单过滤 -> LLM 判级。

    Args:
        report_text: 报告正文
        actor_name: 攻击者名称

    Returns:
        IOC 字典列表
    """
    logger.info("[extract_ioc] 开始为 %s 抽取 IOC...", actor_name)

    # ---- 第一步：正则召回候选 ----
    candidates = extract_all_ioc_candidates(report_text)
    logger.info("[extract_ioc] 正则召回 %d 个候选", len(candidates))

    if not candidates:
        return []

    # ---- 第二步：白名单过滤 ----
    filtered = filter_ioc_candidates(candidates)
    logger.info("[extract_ioc] 白名单过滤后剩余 %d 个", len(filtered))

    if not filtered:
        return []

    # ---- 第三步：LLM 判级 ----
    if not is_llm_available():
        logger.warning("[extract_ioc] LLM 不可用，降级：所有候选标为'未知'")
        return [
            {
                "value": val,
                "type": typ,
                "threat_level": "未知",
                "tags": [],
                "context": None,
            }
            for val, typ in filtered
        ]

    try:
        # 构造候选描述
        candidates_desc = "\n".join(
            f"- {val} (类型: {typ})" for val, typ in filtered[:100]  # 限制传给 LLM 的数量
        )

        client = get_llm_client()
        extractor = client.get_structured_extractor(IOCClassificationResult)
        result = extractor.invoke({
            "ioc_candidates": candidates_desc,
            "context": f"攻击者: {actor_name}",
            "report_text": report_text[:10000],
        })

        if result is None:
            raise RuntimeError("LLM 返回 None")

        iocs = []
        for ioc in result.iocs:
            iocs.append({
                "value": ioc.value,
                "type": ioc.type,
                "threat_level": ioc.threat_level or "未知",
                "tags": ioc.tags,
                "context": ioc.context,
            })

        logger.info("[extract_ioc] %s: LLM 判级 %d 个 IOC", actor_name, len(iocs))
        return iocs

    except Exception as e:
        logger.error("[extract_ioc] %s: LLM 判级失败: %s，降级：标'未知'", actor_name, e)
        return [
            {
                "value": val,
                "type": typ,
                "threat_level": "未知",
                "tags": [],
                "context": None,
            }
            for val, typ in filtered
        ]
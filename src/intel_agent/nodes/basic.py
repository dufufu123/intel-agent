"""
基础信息抽取节点 — LLM 抽 report_name/publish_time/summary/industries/countries

约束：用 structured_output 保证 schema；summary 校验 ≤300 字。
"""

from __future__ import annotations

import logging

from ..llm.client import get_llm_client, is_llm_available
from ..llm.prompts import BASIC_INFO_PROMPT
from ..schemas import BasicInfo

logger = logging.getLogger(__name__)


def extract_basic_node(state: dict) -> dict:
    """
    提取基础信息（LangGraph 节点函数）。

    返回部分 state，框架按 reducer 合并。
    """
    report_text = state.get("report_text", "")
    logger.info("[extract_basic] 开始抽取基础信息...")

    # 降级：LLM 不可用时返回部分结果
    if not is_llm_available():
        logger.warning("[extract_basic] LLM 不可用，降级：返回默认值")
        return {
            "basic": {
                "report_name": "未知",
                "publish_time": "未知",
                "summary": "",
                "targeted_industries": [],
                "targeted_countries": [],
                "confidence": None,
            },
            "errors": ["extract_basic: LLM 不可用，降级返回默认值"],
            "execution_log": ["extract_basic: LLM 不可用，降级"],
        }

    try:
        client = get_llm_client()
        extractor = client.get_structured_extractor(BasicInfo)
        result = extractor.invoke({"report_text": report_text})

        if result is None:
            raise RuntimeError("LLM 返回 None（结构化输出失败）")

        basic_dict = result.model_dump()
        logger.info("[extract_basic] 完成: %s", basic_dict.get("report_name", "未知"))
        return {
            "basic": basic_dict,
            "execution_log": [f"extract_basic 完成: {basic_dict.get('report_name', '未知')}"],
        }

    except Exception as e:
        logger.error("[extract_basic] 失败: %s", e)
        return {
            "basic": {
                "report_name": "未知",
                "publish_time": "未知",
                "summary": "",
                "targeted_industries": [],
                "targeted_countries": [],
                "confidence": None,
            },
            "errors": [f"extract_basic 失败: {e}"],
            "execution_log": [f"extract_basic 失败: {e}"],
        }
"""
ExtractionState — LangGraph 状态定义

约束：
- 多个节点并行写同一字段必须配 reducer，否则后写覆盖先写（fan-out 致命坑）
- fan-out 并写场景：actor_details 按 actor_id 去重归并、errors 追加
- actors 字段仅在 identify_actors 单次 LLM 调用中写入，不存在并行写冲突
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict


def merge_actor_details(left: list[dict], right: list[dict]) -> list[dict]:
    """
    Reducer: 按 actor_id 去重归并 actor_details。

    fan-out 并行写时使用，同 actor_id 后到达的覆盖。
    """
    merged: dict[str, dict] = {}
    for a in left:
        merged[a.get("actor_id", a.get("name", ""))] = a
    for a in right:
        merged[a.get("actor_id", a.get("name", ""))] = a
    return list(merged.values())


class ExtractionState(TypedDict):
    """情报抽取流水线状态"""

    # ---- 输入 ----
    url: str
    """报告 URL"""

    report_text: Optional[str]
    """报告正文纯文本。抓取后填充，或通过 --text 直接传入"""

    # ---- 抓取 ----
    fetch_error: Optional[str]
    """抓取错误信息。非空时 router 早退到 export"""

    # ---- 基础信息 ----
    basic: Optional[dict]
    """基础信息抽取结果（BasicInfo 的 dict 形式）"""

    # ---- 攻击者 ----
    actors: list[dict]
    """
    识别到的攻击者列表（identify_actors 单次 LLM 调用产出）。
    每个元素: {actor_id, name, theme, aliases_matched, is_new_org, new_org_notice,
               iocs, tools, vulnerabilities, ttps}
    tools/vulnerabilities/ttps 在此节点已由 LLM 完整抽取。
    """

    new_org_flags: list[str]
    """新组织提醒列表"""

    # ---- 逐 actor 抽取（fan-out 并行，仅 IOC） ----
    actor_details: Annotated[list[dict], merge_actor_details]
    """
    fan-out 并行抽取的 IOC 详情，reducer 按 actor_id 归并。
    每个元素: {actor_id, name, iocs, tools, vulnerabilities, ttps}
    其中 tools/vulnerabilities/ttps 从 _current_actor 透传，iocs 由 LLM 抽取。
    """

    # ---- 最终输出 ----
    final_report: Optional[dict]
    """聚合后的最终报告（ReportOutput 的 dict 形式）"""

    # ---- 执行状态 ----
    execution_log: Annotated[list[str], operator.add]
    """执行日志（追加）"""

    errors: Annotated[list[str], operator.add]
    """错误列表（追加）"""

    # ---- fan-out 内部使用 ----
    _current_actor: Optional[dict]
    """临时字段：fan-out 分发给 extract_details 的当前 actor 信息"""
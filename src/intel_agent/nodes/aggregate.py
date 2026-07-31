"""
聚合校验导出节点 — 组装 ReportOutput -> Pydantic 校验 -> 去重/补缺省

约束：永远输出合法 JSON，校验不过也要输出带 error 的结构化 JSON，不能崩。
"""

from __future__ import annotations

import logging
from typing import Optional

from ..schemas import (
    IOC,
    TTP,
    ReportOutput,
    ThreatActor,
    ThreatLevelEnum,
    Tool,
    Vulnerability,
)
from ..tools.attack_map import get_attack_map

logger = logging.getLogger(__name__)


def aggregate_node(state: dict) -> dict:
    """
    聚合 + 校验（LangGraph 节点函数）。

    1. 组装 ReportOutput
    2. Pydantic 校验（自动去重、补缺省）
    3. 对 actor_details 中的 TTP 做查表
    4. 返回 final_report
    """
    logger.info("[aggregate] 聚合结果...")

    attack_map = get_attack_map()

    # ---- 构建 ThreatActor 列表 ----
    threator = []
    actor_details = state.get("actor_details", [])

    for ad in actor_details:
        # 转换 IOC
        iocs = []
        for ioc_dict in ad.get("iocs", []):
            iocs.append(IOC(
                value=ioc_dict.get("value", ""),
                type=ioc_dict.get("type", "Domain"),
                threat_level=ioc_dict.get("threat_level", "未知"),
                tags=ioc_dict.get("tags", []),
                context=ioc_dict.get("context"),
            ))

        # 转换工具
        tools = []
        for t_dict in ad.get("tools", []):
            tools.append(Tool(
                name=t_dict.get("name", ""),
                category=t_dict.get("category"),
                description=t_dict.get("description"),
            ))

        # 转换漏洞
        vulnerabilities = []
        for v_dict in ad.get("vulnerabilities", []):
            vulnerabilities.append(Vulnerability(
                cve_id=v_dict.get("cve_id"),
                name=v_dict.get("name"),
            ))

        # 转换 TTP（查表）
        ttps = []
        for ttp_dict in ad.get("ttps", []):
            tech_name = ttp_dict.get("technique_name", "")
            tid = ttp_dict.get("technique_id")
            tactic = ttp_dict.get("tactic")
            is_verified = ttp_dict.get("is_verified", False)

            if not tid and tech_name:
                # 查表
                mapped_id, mapped_tactic = attack_map.lookup_by_name(tech_name)
                if mapped_id:
                    tid = mapped_id
                    if not tactic:
                        tactic = mapped_tactic
                    is_verified = True
                else:
                    # 检查 LLM 是否直出编号
                    if attack_map.is_known_id(tech_name):
                        tid = tech_name
                        is_verified = True

            ttps.append(TTP(
                technique_id=tid,
                technique_name=tech_name,
                tactic=tactic,
                description=ttp_dict.get("description"),
                is_verified=is_verified,
            ))

        threator.append(ThreatActor(
            actor_id=ad.get("actor_id", ""),
            name=ad.get("name", ""),
            aliases_matched=ad.get("aliases_matched", []),
            theme=ad.get("theme", "未知"),
            is_new_org=ad.get("is_new_org", False),
            new_org_notice=ad.get("new_org_notice"),
            iocs=iocs,
            tools=tools,
            vulnerabilities=vulnerabilities,
            ttps=ttps,
        ))

    # ---- 组装 ReportOutput ----
    basic = state.get("basic") or {}

    try:
        report = ReportOutput(
            report_name=basic.get("report_name", "未知报告"),
            publish_time=basic.get("publish_time", "未知"),
            summary=basic.get("summary", ""),
            targeted_industries=basic.get("targeted_industries", []),
            targeted_countries=basic.get("targeted_countries", []),
            threator=threator,
            new_org_flags=state.get("new_org_flags", []),
            errors=state.get("errors", []),
        )

        report_dict = report.model_dump()
        logger.info(
            "[aggregate] 完成: %d 个攻击者, %d 个新组织提醒",
            len(report_dict.get("threator", [])),
            len(report_dict.get("new_org_flags", [])),
        )

        return {
            "final_report": report_dict,
            "execution_log": ["aggregate 完成"],
        }

    except Exception as e:
        # 校验不过也要输出结构化 JSON
        logger.error("[aggregate] Pydantic 校验失败: %s", e)
        error_report = {
            "report_name": basic.get("report_name", "未知报告"),
            "publish_time": basic.get("publish_time", "未知"),
            "summary": basic.get("summary", ""),
            "targeted_industries": basic.get("targeted_industries", []),
            "targeted_countries": basic.get("targeted_countries", []),
            "threator": [],
            "new_org_flags": state.get("new_org_flags", []),
            "errors": state.get("errors", []) + [f"aggregate 校验失败: {e}"],
        }
        return {
            "final_report": error_report,
            "errors": [f"aggregate 校验失败: {e}"],
            "execution_log": [f"aggregate 校验失败: {e}"],
        }
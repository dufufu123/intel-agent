"""
导出归档 — 序列化 JSON / 生成 MD / 按日期归档

约束：经 Pydantic 校验后再导出。
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from loguru import logger


def slugify(name: str) -> str:
    """生成文件名安全 slug"""
    import re
    name = re.sub(r'[^\w\s\-]', '', name)
    name = re.sub(r'[\s]+', '-', name.strip())
    return name[:60]


def get_output_dir(base_dir: str | Path = "output") -> Path:
    """获取按日期归档的输出目录"""
    today = date.today().isoformat()
    out = Path(base_dir) / today
    out.mkdir(parents=True, exist_ok=True)
    return out


def export_json(
    report: dict,
    output_dir: str | Path = "output",
    filename: Optional[str] = None,
) -> Path:
    """
    导出 JSON 文件。

    Args:
        report: 最终报告 dict
        output_dir: 输出根目录
        filename: 文件名（不含扩展名），默认用 report_name slug

    Returns:
        输出文件路径
    """
    out_dir = get_output_dir(output_dir)

    if filename is None:
        report_name = report.get("report_name", "unknown")
        filename = slugify(report_name) or "report"

    # 确保文件名唯一
    path = out_dir / f"{filename}.json"
    counter = 1
    while path.exists():
        path = out_dir / f"{filename}-{counter}.json"
        counter += 1

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info("JSON 已导出: {}", path)
    return path


def export_markdown(report: dict, output_dir: str | Path = "output") -> Path:
    """
    生成 Markdown 格式报告。

    Args:
        report: 最终报告 dict
        output_dir: 输出根目录

    Returns:
        输出文件路径
    """
    out_dir = get_output_dir(output_dir)
    report_name = report.get("report_name", "unknown")
    filename = slugify(report_name) or "report"

    path = out_dir / f"{filename}.md"
    counter = 1
    while path.exists():
        path = out_dir / f"{filename}-{counter}.md"
        counter += 1

    lines = []
    lines.append(f"# {report.get('report_name', '未知报告')}")
    lines.append("")
    lines.append(f"**发布时间**: {report.get('publish_time', '未知')}")
    lines.append("")
    lines.append(f"**概述**: {report.get('summary', '无')}")
    lines.append("")

    if report.get("targeted_industries"):
        lines.append("**目标行业**: " + ", ".join(report["targeted_industries"]))
        lines.append("")

    if report.get("targeted_countries"):
        lines.append("**涉及国家/地区**: " + ", ".join(report["targeted_countries"]))
        lines.append("")

    # 攻击者
    threator = report.get("threator", [])
    if threator:
        lines.append("---")
        lines.append("")
        lines.append("## 威胁行为者")
        lines.append("")

        for actor in threator:
            lines.append(f"### {actor.get('name', '未知')}")
            lines.append("")
            lines.append(f"- **类型**: {actor.get('theme', '未知')}")
            if actor.get("is_new_org"):
                lines.append(f"- **⚠️ 新组织**: {actor.get('new_org_notice', '该组织可能是新组织，建议核实后更新攻击组织档案库')}")
            lines.append("")

            # IOC
            iocs = actor.get("iocs", [])
            if iocs:
                lines.append("#### IOC")
                lines.append("")
                lines.append("| 值 | 类型 | 威胁等级 | 标签 |")
                lines.append("|---|---|---|---|")
                for ioc in iocs:
                    tags = ", ".join(ioc.get("tags", []))
                    lines.append(
                        f"| `{ioc.get('value', '')}` | {ioc.get('type', '')} | "
                        f"{ioc.get('threat_level', '未知')} | {tags} |"
                    )
                lines.append("")

            # 工具
            tools = actor.get("tools", [])
            if tools:
                lines.append("#### 工具/恶意软件")
                lines.append("")
                for t in tools:
                    lines.append(f"- **{t.get('name', '')}** ({t.get('category', '未知')}): {t.get('description', '')}")
                lines.append("")

            # 漏洞
            vulns = actor.get("vulnerabilities", [])
            if vulns:
                lines.append("#### 漏洞")
                lines.append("")
                for v in vulns:
                    cve = v.get("cve_id", "") or ""
                    vname = v.get("name", "") or ""
                    header = f"{cve} {vname}".strip()
                    lines.append(f"- **{header}**: {v.get('description', '')}")
                lines.append("")

            # TTP
            ttps = actor.get("ttps", [])
            if ttps:
                lines.append("#### ATT&CK 技战术")
                lines.append("")
                lines.append("| 编号 | 技术名 | 战术 |")
                lines.append("|---|---|---|")
                for ttp in ttps:
                    tid = ttp.get("technique_id", "?") or "?"
                    lines.append(
                        f"| {tid} | {ttp.get('technique_name', '')} | "
                        f"{ttp.get('tactic', '') or ''} |"
                    )
                lines.append("")

    # 新组织提醒
    new_org_flags = report.get("new_org_flags", [])
    if new_org_flags:
        lines.append("---")
        lines.append("")
        lines.append("## ⚠️ 新组织提醒")
        lines.append("")
        for flag in new_org_flags:
            lines.append(f"- {flag}")
        lines.append("")

    # 错误
    errors = report.get("errors", [])
    if errors:
        lines.append("---")
        lines.append("")
        lines.append("## 错误")
        lines.append("")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")

    content = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info("Markdown 已导出: {}", path)
    return path
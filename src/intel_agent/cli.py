"""
CLI 入口 — 参数解析、env 加载、graph 装配、批量循环、断点续跑

约束：不放业务逻辑，只做装配与 IO；批量任务单篇失败不中断。
用法：
  python -m intel_agent <url>
  python -m intel_agent -f urls.txt
  python -m intel_agent --text "报告正文..."
  python -m intel_agent <url> --no-resume   # 强制全新运行，忽略断点
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from loguru import logger

from .graph import build_graph, get_default_graph
from .output.exporter import export_json, export_markdown
from .output.logging import setup_logging
from .state import ExtractionState


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        prog="intel-agent",
        description="威胁情报抽取 Agent — 从安全报告中提取结构化情报",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m intel_agent https://example.com/report.html
  python -m intel_agent -f urls.txt
  python -m intel_agent --text "报告正文..."
  python -m intel_agent https://example.com/report.html --format md --verbose
        """,
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="报告 URL",
    )
    parser.add_argument(
        "-f", "--file",
        dest="urls_file",
        metavar="FILE",
        help="批量 URL 文件（每行一个 URL）",
    )
    parser.add_argument(
        "--text",
        metavar="TEXT",
        help="直接输入报告正文（跳过 URL 抓取）",
    )
    parser.add_argument(
        "--format",
        choices=["json", "md", "both"],
        default="json",
        help="输出格式（默认 json）",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        metavar="DIR",
        help="输出目录（默认 output/）",
    )
    parser.add_argument(
        "--db",
        default="checkpoints.db",
        metavar="PATH",
        help="checkpointer 数据库路径（默认 checkpoints.db）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="输出详细日志",
    )
    parser.add_argument(
        "--no-checkpointer",
        action="store_true",
        help="禁用断点续跑",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="强制全新运行，忽略已有断点",
    )
    parser.add_argument(
        "--mermaid",
        action="store_true",
        help="输出 Mermaid 流程图并退出",
    )

    return parser.parse_args(argv)


def create_initial_state(
    url: str = "",
    report_text: Optional[str] = None,
) -> dict:
    """创建初始状态"""
    initial: ExtractionState = {
        "url": url,
        "report_text": report_text,
        "fetch_error": None,
        "basic": None,
        "actors": [],
        "new_org_flags": [],
        "actor_details": [],
        "final_report": None,
        "execution_log": [],
        "errors": [],
        "_current_actor": None,
    }
    return initial


def process_single(
    url: str,
    report_text: Optional[str],
    output_dir: str,
    output_format: str,
    db_path: str,
    no_checkpointer: bool,
    no_resume: bool = False,
) -> Optional[dict]:
    """
    处理单个 URL/文本。支持断点续跑。

    Args:
        url: 报告 URL
        report_text: 直接传入的正文（跳过抓取）
        output_dir: 输出目录
        output_format: 输出格式
        db_path: checkpointer 数据库路径
        no_checkpointer: 是否禁用 checkpointer
        no_resume: 是否强制全新运行（忽略断点）

    Returns:
        最终报告 dict，或 None 表示失败
    """
    logger.info("=" * 60)
    logger.info("开始处理: {}", url or "（直接输入文本）")
    logger.info("=" * 60)

    # 构建 graph
    if no_checkpointer:
        from langgraph.checkpoint.memory import MemorySaver
        graph = build_graph(checkpointer=MemorySaver())
    else:
        graph = build_graph(db_path=db_path)

    # 初始状态
    initial = create_initial_state(url=url, report_text=report_text)

    # thread_id: URL 作为唯一标识，文本用 hash
    if report_text and not url:
        base_thread_id = f"text-{hash(report_text) % 100000}"
    else:
        base_thread_id = url

    # 强制全新运行：追加时间戳，这样不会命中旧断点
    if no_resume:
        thread_id = f"{base_thread_id}-{int(time.time())}"
        logger.info("--no-resume 模式，thread_id={}", thread_id)
    else:
        thread_id = base_thread_id

    config = {"configurable": {"thread_id": thread_id}}

    # ---- 检查是否存在断点 ----
    is_resuming = False
    if not no_checkpointer and not no_resume:
        try:
            current_state = graph.get_state(config)
            if current_state is not None and current_state.next:
                # 有未完成的节点 → 断点存在，恢复
                completed_steps = [
                    k for k, v in (current_state.values or {}).items()
                    if v and k not in ("execution_log", "errors")
                ]
                logger.info(
                    "检测到断点: 已完成 {}，将从 '{}' 恢复",
                    completed_steps or "（无）",
                    list(current_state.next),
                )
                is_resuming = True
            elif current_state is not None and (current_state.values or {}).get("final_report"):
                # 上次已完成（无待执行节点 + 已有 final_report）
                # 换新 thread_id 全新运行，避免累积历史 errors/execution_log
                thread_id = f"{base_thread_id}-{int(time.time())}"
                config = {"configurable": {"thread_id": thread_id}}
                logger.info("检测到上次已完成，换新 thread_id={} 重新开始", thread_id)
        except Exception as e:
            # get_state 可能因版本差异或首次运行失败，忽略
            logger.debug("检查断点状态时出现预期内异常: {}", e)

    # ---- 执行流水线 ----
    try:
        if is_resuming:
            logger.info("从断点恢复执行...")
            result = graph.invoke(None, config)
        else:
            logger.info("全新执行...")
            result = graph.invoke(initial, config)
    except Exception as e:
        logger.error("流水线执行异常: {}", e)
        if not no_checkpointer and not is_resuming:
            logger.info(
                "已保存断点。使用相同命令重新运行即可从断点恢复，"
                "或使用 --no-resume 强制全新运行。"
            )
        error_report = {
            "error": str(e),
            "url": url or "（文本输入）",
            "errors": [str(e)],
        }
        return error_report

    # 获取最终报告
    final_report = result.get("final_report") or {}

    # 导出
    if output_format in ("json", "both"):
        export_json(final_report, output_dir=output_dir)

    if output_format in ("md", "both"):
        export_markdown(final_report, output_dir=output_dir)

    # 打印执行摘要
    errors = result.get("errors", [])
    if errors:
        logger.warning("执行中遇到 {} 个错误", len(errors))

    log = result.get("execution_log", [])
    logger.info("执行日志: {}", " | ".join(log))

    return final_report


def process_batch(
    urls: list[str],
    output_dir: str,
    output_format: str,
    db_path: str,
    no_checkpointer: bool,
    no_resume: bool = False,
) -> list[dict]:
    """
    批量处理 URL 列表。

    单篇失败不中断，捕获后记错继续。
    """
    results = []
    total = len(urls)

    for i, url in enumerate(urls, 1):
        url = url.strip()
        if not url or url.startswith("#"):
            continue

        logger.info("批量进度: {}/{}", i, total)
        try:
            result = process_single(
                url=url,
                report_text=None,
                output_dir=output_dir,
                output_format=output_format,
                db_path=db_path,
                no_checkpointer=no_checkpointer,
                no_resume=no_resume,
            )
            results.append(result or {"error": "unknown", "url": url})
        except Exception as e:
            logger.error("批量处理 {} 失败: {}", url, e)
            results.append({"error": str(e), "url": url})

    return results


def main(argv: list[str] | None = None) -> int:
    """主入口"""
    args = parse_args(argv)

    # 加载环境变量
    load_dotenv()

    # 日志
    setup_logging(
        level="DEBUG" if args.verbose else "INFO",
        verbose=args.verbose,
    )

    # Mermaid 流程图
    if args.mermaid:
        graph = get_default_graph()
        print(graph.get_graph().draw_mermaid())
        return 0

    # 批量模式
    if args.urls_file:
        path = Path(args.urls_file)
        if not path.exists():
            logger.error("URL 文件不存在: {}", args.urls_file)
            return 1

        with open(path, encoding="utf-8") as f:
            urls = f.readlines()

        logger.info("批量模式: {} 个 URL", len(urls))
        results = process_batch(
            urls=urls,
            output_dir=args.output_dir,
            output_format=args.format,
            db_path=args.db,
            no_checkpointer=args.no_checkpointer,
            no_resume=args.no_resume,
        )

        success = sum(1 for r in results if "error" not in r)
        logger.info("批量完成: {}/{} 成功", success, len(results))
        return 0 if success == len(results) else 1

    # 单篇模式
    if args.text:
        # 直接输入文本
        result = process_single(
            url="",
            report_text=args.text,
            output_dir=args.output_dir,
            output_format=args.format,
            db_path=args.db,
            no_checkpointer=args.no_checkpointer,
            no_resume=args.no_resume,
        )
    elif args.url:
        result = process_single(
            url=args.url,
            report_text=None,
            output_dir=args.output_dir,
            output_format=args.format,
            db_path=args.db,
            no_checkpointer=args.no_checkpointer,
            no_resume=args.no_resume,
        )
    else:
        logger.error("请提供 URL 或 --text 参数，或使用 -f 指定批量文件")
        return 1

    if result is None:
        return 1

    if "error" in result:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
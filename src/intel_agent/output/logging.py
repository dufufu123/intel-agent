"""
日志配置 — loguru

约束：节点入口/出口、LLM 调用、失败降级都打日志。
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger


def setup_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    verbose: bool = False,
) -> None:
    """
    配置 loguru 日志。

    Args:
        level: 日志级别
        log_file: 日志文件路径，默认 output/logs/intel_agent_{date}.log
        verbose: 是否输出 DEBUG 级别日志到 stderr
    """
    # 移除默认 handler
    logger.remove()

    # 控制台输出
    if verbose:
        logger.add(
            sys.stderr,
            level="DEBUG",
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            colorize=True,
        )
    else:
        logger.add(
            sys.stderr,
            level=level,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            colorize=True,
        )

    # 文件输出
    if log_file is None:
        from datetime import date
        log_dir = Path("output") / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"intel_agent_{date.today().isoformat()}.log"

    logger.add(
        str(log_file),
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
        rotation="10 MB",
        retention="30 days",
        encoding="utf-8",
    )

    logger.info("日志系统初始化完成，文件: {}", log_file)


def get_logger(name: str = "intel_agent"):
    """获取 logger 实例"""
    return logger.bind(name=name)
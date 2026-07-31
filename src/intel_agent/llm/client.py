"""
LLM 客户端 — DeepSeek (OpenAI 兼容) + with_structured_output + 重试 + 降级

约束：
- OpenAI 兼容接口，env 可切换不改正代码
- 重试与降级都要有（稳定性评分点）
- with_structured_output 保证结构化输出
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Type, TypeVar

from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# 类型变量：Pydantic 模型类型
T = TypeVar("T", bound=BaseModel)

# 默认配置
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_TIMEOUT = 90
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_RETRIES = 3

# LLM 不可用的标志
_llm_unavailable: bool = False


def _load_api_key() -> str:
    """
    加载 API Key，优先级：
    1. 环境变量 DEEPSEEK_API_KEY
    2. 项目根目录 apkey.txt
    """
    key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if key:
        return key

    # 尝试从 apkey.txt 读取
    key_paths = [
        Path(__file__).parent.parent.parent.parent / "apkey.txt",
        Path("apkey.txt"),
    ]
    for p in key_paths:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                key = f.read().strip()
            if key:
                return key

    return ""


class LLMClient:
    """
    LLM 客户端封装

    功能：
    - 装配 DeepSeek 客户端
    - 提供各步的 with_structured_output 实例
    - 指数退避重试
    - LLM 不可用时的降级
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        temperature: float = DEFAULT_TEMPERATURE,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self._base_url = base_url or os.getenv("LLM_BASE_URL", DEFAULT_BASE_URL)
        self._model = model or os.getenv("LLM_MODEL", DEFAULT_MODEL)
        self._api_key = api_key or _load_api_key()
        self._timeout = timeout
        self._temperature = temperature
        self._max_retries = max_retries

        self._llm: ChatOpenAI | None = None
        self._available = bool(self._api_key)

        if self._available:
            self._init_llm()
        else:
            logger.warning("未找到 DEEPSEEK_API_KEY，LLM 功能不可用，将使用降级模式")

    def _init_llm(self) -> None:
        """初始化 ChatOpenAI 实例"""
        self._llm = ChatOpenAI(
            base_url=self._base_url,
            model=self._model,
            api_key=self._api_key,
            timeout=self._timeout,
            temperature=self._temperature,
            max_retries=0,  # 我们自己用 tenacity 管理重试
        )

    @property
    def is_available(self) -> bool:
        return self._available and self._llm is not None

    def get_structured_extractor(self, schema: Type[T]) -> "StructuredExtractor[T]":
        """
        获取结构化抽取器。

        Args:
            schema: Pydantic 模型类

        Returns:
            StructuredExtractor 实例，支持 .invoke() 调用
        """
        return StructuredExtractor(
            llm=self._llm,
            schema=schema,
            available=self._available,
            max_retries=self._max_retries,
        )


class StructuredExtractor:
    """
    结构化抽取器 — 封装 with_structured_output + tenacity 重试 + 降级

    用法：
        extractor = client.get_structured_extractor(BasicInfo)
        result = extractor.invoke({"text": "..."})
    """

    def __init__(
        self,
        llm: ChatOpenAI | None,
        schema: Type[T],
        available: bool,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self._schema = schema
        self._available = available
        self._max_retries = max_retries
        self._structured_llm = None

        if available and llm is not None:
            # DeepSeek 不支持 OpenAI 的 json_schema 模式，必须用 function_calling
            self._structured_llm = llm.with_structured_output(
                schema, method="function_calling"
            )

    def invoke(self, input_data: dict) -> T | None:
        """
        调用 LLM 做结构化抽取。

        Args:
            input_data: prompt 模板变量

        Returns:
            Pydantic 模型实例，或降级时返回 None
        """
        if not self._available or self._structured_llm is None:
            logger.warning("LLM 不可用，降级：返回 None for %s", self._schema.__name__)
            return None

        @retry(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type((Exception,)),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            reraise=True,
        )
        def _invoke_with_retry() -> T:
            return self._structured_llm.invoke(input_data)

        try:
            return _invoke_with_retry()
        except Exception as e:
            logger.error("LLM 调用最终失败 (%s): %s", self._schema.__name__, e)
            return None


# 全局单例
_llm_client: LLMClient | None = None


def get_llm_client(
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    temperature: float = DEFAULT_TEMPERATURE,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> LLMClient:
    """获取 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=timeout,
            temperature=temperature,
            max_retries=max_retries,
        )
    return _llm_client


def is_llm_available() -> bool:
    """检查 LLM 是否可用"""
    return get_llm_client().is_available
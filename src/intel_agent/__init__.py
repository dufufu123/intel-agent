"""
intel_agent — 威胁情报抽取 Agent

六层解耦框架：
1. 交互入口  CLI(python -m intel_agent <url>)
2. 编排      LangGraph 状态机（分步抽取流水线 + 早退短路 + fan-out）
3. 抽取能力  LLM 抽取器(prompt+structured_output) + 纯 Python 辅助
4. 工具数据  fetcher / actor_config(热加载) / ioc_regex / whitelist / attack_map
5. LLM 模型  ChatOpenAI(DeepSeek) + with_structured_output + 重试 + 降级
6. 输出存储  JSON(Pydantic 校验) + 可选 MD + loguru 日志 + output/ 归档
"""

__version__ = "0.1.0"
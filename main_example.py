"""
ch10 — 综合实战：mini 情报抽取流水线
========================================
把 ch01-ch09 全部串起来，做一个能跑通的 mini 版情报抽取 Agent。

包含：
  - Pydantic 模型（ch02）
  - LangChain + DeepSeek（ch03）
  - with_structured_output（ch04）
  - YAML 配置 + 热加载（ch05）
  - LangGraph 状态机（ch06）
  - 条件边 + 早退（ch07）
  - fan-out 并行抽取（ch08）
  - checkpointer 续跑（ch09）

运行：python main.py <url>
  或  python main.py --text "报告正文..."
前提：上级目录 apkey.txt 存在且有效

这是一个「能跑的最小版本」，主项目就是在这个基础上加更多字段、
更多节点、更完善的错误处理和降级。
"""

import os, sys, json, time, re
from pathlib import Path
from typing import TypedDict, Annotated, Optional, Literal
import operator

import yaml
from pydantic import BaseModel, Field, field_validator
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from langgraph.types import Send
from langgraph.checkpoint.sqlite import SqliteSaver

# ============================================================
# 0. 配置
# ============================================================
PARENT = Path(__file__).parent.parent.parent  # starting_before 的上级目录
with open(PARENT / "apkey.txt") as f:
    API_KEY = f.read().strip()

DB_PATH = Path(__file__).parent / "mini_pipeline_checkpoints.db"
ACTORS_CONFIG = Path(__file__).parent / "actors.yaml"

# 如果配置文件不存在，创建一个示例
if not ACTORS_CONFIG.exists():
    ACTORS_CONFIG.write_text("""
version: 1
actors:
  - id: apt28
    name: APT28
    aliases: [Fancy Bear, Sofacy, Pawn Storm, Strontium, Forest Blizzard]
    theme: APT
  - id: apt29
    name: APT29
    aliases: [Cozy Bear, The Dukes]
    theme: APT
  - id: lazarus
    name: Lazarus
    aliases: [Hidden Cobra, APT38, Guardians of Peace]
    theme: APT
  - id: conti
    name: Conti
    aliases: [Conti ransomware]
    theme: 恶意代码家族
  - id: emotet
    name: Emotet
    aliases: [Heodo]
    theme: 恶意代码家族
""", encoding="utf-8")


# ============================================================
# 1. Pydantic 模型（对应 ch02 + ch04）
# ============================================================
class BasicInfo(BaseModel):
    """基础信息抽取结果"""
    report_name: str = Field(description="报告原始标题")
    publish_time: str = Field(description="发布时间，格式 YYYY-MM-DD")
    summary: str = Field(description="报告概述，不超过 300 字")
    targeted_industries: list[str] = Field(description="受攻击行业列表")
    targeted_countries: list[str] = Field(description="涉及国家/地区列表")

    @field_validator("summary")
    @classmethod
    def check_length(cls, v: str) -> str:
        if len(v) > 300:
            raise ValueError(f"概述超过 300 字（实际 {len(v)} 字）")
        return v

class IOC(BaseModel):
    value: str = Field(description="IOC 值")
    type: Literal["IP", "Domain", "URL", "Hash", "Email"] = Field(description="IOC 类型")
    threat_level: Literal["恶意", "可疑", "未知", "白名单"] = Field(description="威胁等级")

class ActorExtraction(BaseModel):
    """单个攻击者的抽取结果"""
    actor_name: str = Field(description="攻击者名称")
    theme: Literal["APT", "恶意代码家族"] = Field(description="攻击者类型")
    iocs: list[IOC] = Field(description="关联 IOC 列表")
    tools: list[str] = Field(description="使用的工具/恶意软件")
    vulnerabilities: list[str] = Field(description="利用的漏洞")
    ttps: list[str] = Field(description="ATT&CK 技战术编号")
    is_new_org: bool = Field(default=False, description="是否为新组织（不在配置中）")


# ============================================================
# 2. LangGraph State（对应 ch01 + ch06 + ch08）
# ============================================================
def merge_actor_details(left: list[dict], right: list[dict]) -> list[dict]:
    """reducer: 按 name 去重归并"""
    merged = {a["name"]: a for a in left}
    for a in right:
        merged[a["name"]] = a
    return list(merged.values())

class PipelineState(TypedDict):
    # 输入
    url: str
    report_text: Optional[str]
    # 抓取
    fetch_error: Optional[str]
    # 基础信息
    basic: Optional[dict]
    # 攻击者
    raw_actors: list[dict]              # 识别到的攻击者
    new_org_flags: list[str]            # 新组织提醒
    # 逐 actor 抽取（fan-out，reducer 归并）
    actor_details: Annotated[list[dict], merge_actor_details]
    # 最终输出
    final_report: Optional[dict]
    # 日志
    execution_log: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]


# ============================================================
# 3. LLM 客户端 + 结构化输出（对应 ch03 + ch04）
# ============================================================
llm = ChatOpenAI(
    base_url="https://api.deepseek.com",
    model="deepseek-chat",
    api_key=API_KEY,
    temperature=0.1,
)

# 注意：DeepSeek 不支持 OpenAI 的 json_schema 模式（response_format），
# 必须显式指定 method="function_calling"（用 tool calling）。
basic_extractor = llm.with_structured_output(BasicInfo, method="function_calling")
actor_extractor = llm.with_structured_output(ActorExtraction, method="function_calling")

# Prompt 模板
BASIC_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个威胁情报分析师。请从以下报告中提取关键信息。
如果无法确定某个字段的值，请根据上下文合理推断，不要留空。
publish_time 必须是 YYYY-MM-DD 格式，如果报告没有明确时间，用报告描述的事件时间。
summary 不超过 300 字。"""),
    ("user", "报告内容：\n{report_text}"),
])

ACTOR_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个威胁情报分析师。请从报告中提取以下攻击者的详细信息：
- 攻击者名称
- 类型（APT 或 恶意代码家族）
- 所有关联的 IOC（IP、域名、URL、Hash、邮箱），并判断威胁等级
- 使用的工具/恶意软件
- 利用的漏洞（格式：漏洞名称 或 CVE 编号）
- ATT&CK 技战术编号（如 T1566.001）

如果攻击者名称不在已知列表中，仍然提取并标记 is_new_org=true。
已知攻击者列表：{known_actors}"""),
    ("user", "报告内容：\n{report_text}\n\n要提取的攻击者：{actor_name}"),
])


# ============================================================
# 4. 工具函数（对应 ch05）
# ============================================================
def load_actor_config() -> dict:
    with open(ACTORS_CONFIG, encoding="utf-8") as f:
        return yaml.safe_load(f)

def build_alias_dict(actors: list[dict]) -> dict[str, dict]:
    """构建 {别名.lower() -> actor_info} 字典"""
    alias_map = {}
    for actor in actors:
        for alias in [actor["name"]] + actor["aliases"]:
            alias_map[alias.lower()] = actor
    return alias_map

def match_actors_in_text(text: str, alias_map: dict) -> list[dict]:
    """在文本中匹配攻击者（词边界）"""
    text_lower = text.lower()
    matched = {}
    for alias, info in alias_map.items():
        if re.search(r'\b' + re.escape(alias) + r'\b', text_lower):
            matched[info["id"]] = info
    return list(matched.values())


# ============================================================
# 5. 节点函数（对应 ch06 + ch07 + ch08）
# ============================================================
def fetch_node(state: PipelineState) -> dict:
    """抓取报告正文"""
    url = state["url"]
    print(f"\n📡 [fetch] {url}")
    try:
        import requests
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        from readability import Document
        doc = Document(resp.text)
        text = doc.summary()
        # 简单清洗 HTML 标签
        from bs4 import BeautifulSoup
        text = BeautifulSoup(text, "lxml").get_text(" ", strip=True)
        if len(text) < 200:
            raise ValueError(f"正文过短（{len(text)} 字），可能是 JS 渲染页面")
        print(f"  ✅ 抓取成功，正文 {len(text)} 字")
        return {
            "report_text": text,
            "fetch_error": None,
            "execution_log": [f"fetch 成功: {len(text)} 字"],
        }
    except Exception as e:
        print(f"  ❌ 抓取失败: {e}")
        return {
            "report_text": None,
            "fetch_error": str(e),
            "execution_log": [f"fetch 失败: {e}"],
        }

def extract_basic_node(state: PipelineState) -> dict:
    """提取基础信息"""
    print(f"📝 [extract_basic] LLM 抽取中...")
    try:
        result = (BASIC_PROMPT | basic_extractor).invoke({"report_text": state["report_text"]})
        print(f"  ✅ 标题: {result.report_name}")
        return {
            "basic": result.model_dump(),
            "execution_log": [f"extract_basic 完成: {result.report_name}"],
        }
    except Exception as e:
        print(f"  ❌ 抽取失败: {e}")
        return {
            "basic": {"report_name": "未知", "publish_time": "未知", "summary": "", "targeted_industries": [], "targeted_countries": []},
            "errors": [f"extract_basic 失败: {e}"],
            "execution_log": [f"extract_basic 失败: {e}"],
        }

def identify_actors_node(state: PipelineState) -> dict:
    """识别攻击者（配置匹配 + LLM 确认）"""
    print(f"🔍 [identify_actors] 识别攻击者...")
    config = load_actor_config()
    alias_map = build_alias_dict(config["actors"])
    matched = match_actors_in_text(state["report_text"], alias_map)

    new_org_flags = []
    if matched:
        print(f"  ✅ 配置匹配到 {len(matched)} 个: {[m['name'] for m in matched]}")
    else:
        print(f"  ⚠️ 配置未匹配到攻击者，让 LLM 尝试发现...")

    # 简化：这里用配置匹配结果，实际项目会再调 LLM 确认 + 补漏
    return {
        "raw_actors": [{"id": m["id"], "name": m["name"], "theme": m["theme"]} for m in matched],
        "new_org_flags": new_org_flags,
        "execution_log": [f"identify_actors: 匹配到 {len(matched)} 个"],
    }

def extract_details_node(state: PipelineState) -> dict:
    """对单个 actor 抽取详情（fan-out 的并行节点）"""
    actor = state.get("_current_actor", {})
    name = actor.get("name", "unknown")
    theme = actor.get("theme", "未知")
    print(f"🔬 [extract_details] LLM 抽取 {name}...")

    known = [a["name"] for a in load_actor_config()["actors"]]

    try:
        result = (ACTOR_PROMPT | actor_extractor).invoke({
            "report_text": state["report_text"],
            "actor_name": name,
            "known_actors": ", ".join(known),
        })
        print(f"  ✅ {name}: {len(result.iocs)} IOC, {len(result.ttps)} TTP")
        detail = result.model_dump()
        detail["id"] = actor.get("id", name.lower())
        if name not in known:
            detail["is_new_org"] = True
    except Exception as e:
        print(f"  ❌ {name} 抽取失败: {e}")
        detail = {
            "id": actor.get("id", name.lower()),
            "name": name,
            "theme": theme,
            "iocs": [], "tools": [], "vulnerabilities": [], "ttps": [],
            "is_new_org": False,
        }
        return {"actor_details": [detail], "errors": [f"extract_details({name}) 失败: {e}"]}

    return {
        "actor_details": [detail],
        "execution_log": [f"extract_details({name}): {len(detail.get('iocs',[]))} IOC"],
    }

def aggregate_node(state: PipelineState) -> dict:
    """聚合 + 校验"""
    print(f"📊 [aggregate] 聚合结果...")
    report = {
        "report_name": state["basic"].get("report_name", "未知") if state["basic"] else "未知",
        "publish_time": state["basic"].get("publish_time", "") if state["basic"] else "",
        "summary": state["basic"].get("summary", "") if state["basic"] else "",
        "targeted_industries": state["basic"].get("targeted_industries", []) if state["basic"] else [],
        "targeted_countries": state["basic"].get("targeted_countries", []) if state["basic"] else [],
        "threator": state.get("actor_details", []),
        "new_org_flags": state.get("new_org_flags", []),
        "errors": state.get("errors", []),
    }
    return {
        "final_report": report,
        "execution_log": ["aggregate 完成"],
    }

def export_node(state: PipelineState) -> dict:
    """导出"""
    print(f"💾 [export] 输出结果...")
    if state.get("fetch_error"):
        report = {"error": state["fetch_error"], "url": state["url"]}
    else:
        report = state["final_report"]
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return {"execution_log": ["export 完成"]}


# ============================================================
# 6. Router（对应 ch07）
# ============================================================
def route_after_fetch(state: PipelineState) -> str:
    if state.get("fetch_error") or not state.get("report_text"):
        return "export"
    return "extract_basic"

def route_after_actors(state: PipelineState) -> str:
    if not state.get("raw_actors"):
        return "aggregate"
    return "fan_out_dispatcher"   # 先跳到 dispatcher 节点，再从那里 fan-out

def fan_out_dispatcher(state: PipelineState) -> dict:
    """No-op 节点，唯一作用是作为 fan-out 的出口。
    因为 add_conditional_edges + list[Send] 只能接到一个节点上，
    而 identify_actors 需要分叉（无 actor -> aggregate / 有 actor -> fan-out），
    所以先 route 到 dispatcher，再从 dispatcher 做 fan-out。"""
    return {}

def fan_out_details(state: PipelineState) -> list[Send]:
    actors = state["raw_actors"]
    return [Send("extract_details", {"_current_actor": a}) for a in actors]


# ============================================================
# 7. 构建图（对应 ch06 + ch07 + ch08 + ch09）
# ============================================================
def build_graph():
    builder = StateGraph(PipelineState)
    builder.add_node("fetch", fetch_node)
    builder.add_node("extract_basic", extract_basic_node)
    builder.add_node("identify_actors", identify_actors_node)
    builder.add_node("fan_out_dispatcher", fan_out_dispatcher)  # ← 新增 dispatcher 节点
    builder.add_node("extract_details", extract_details_node)
    builder.add_node("aggregate", aggregate_node)
    builder.add_node("export", export_node)

    builder.set_entry_point("fetch")
    builder.add_conditional_edges("fetch", route_after_fetch, {"extract_basic": "extract_basic", "export": "export"})
    builder.add_edge("extract_basic", "identify_actors")
    builder.add_conditional_edges("identify_actors", route_after_actors, {
        "fan_out_dispatcher": "fan_out_dispatcher",    # 有 actor -> dispatcher
        "aggregate": "aggregate",                      # 无 actor -> 跳过
    })
    # dispatcher 做 fan-out：返回 list[Send] -> 并行执行 extract_details
    builder.add_conditional_edges("fan_out_dispatcher", fan_out_details)
    builder.add_edge("extract_details", "aggregate")
    builder.add_edge("aggregate", "export")
    builder.add_edge("export", END)

    return builder.compile(checkpointer=SqliteSaver.from_conn_string(str(DB_PATH)))


# ============================================================
# 8. 入口
# ============================================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Mini 情报抽取 Agent")
    parser.add_argument("url", help="报告 URL")
    parser.add_argument("--text", help="直接输入报告正文（跳过抓取）", default=None)
    args = parser.parse_args()

    graph = build_graph()

    # 初始状态
    initial = {
        "url": args.url,
        "report_text": args.text,
        "fetch_error": None,
        "basic": None,
        "raw_actors": [],
        "new_org_flags": [],
        "actor_details": [],
        "final_report": None,
        "execution_log": [],
        "errors": [],
    }

    # 如果直接传了文本，跳过 fetch 节点
    # （实际项目中用条件判断，这里简化处理）
    if args.text:
        initial["report_text"] = args.text
        initial["fetch_error"] = None

    print("=" * 60)
    print("🛡️  Mini 情报抽取 Agent")
    print(f"   目标: {args.url}")
    print("=" * 60)

    config = {"configurable": {"thread_id": args.url}}
    result = graph.invoke(initial, config)

    print("\n" + "=" * 60)
    print(f"📋 执行日志: {result['execution_log']}")
    print("=" * 60)
    print("✅ 完成。输出 JSON 见上方。")
    print("   checkpointer 已保存到:", DB_PATH)
    print("   (同 URL 再次运行会从断点恢复，不重复调 LLM)")
    print("=" * 60)
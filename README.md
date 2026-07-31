# intel-agent — 威胁情报抽取 Agent

从安全报告中自动提取结构化威胁情报：攻击者、IOC、工具、漏洞、ATT&CK 技战术。

## 架构

六层解耦、独立自包含：

```
交互入口  CLI (python -m intel_agent <url>) / 批量 (-f urls.txt) / 可选 Streamlit
编排      LangGraph 状态机（分步抽取流水线 + 早退短路 + fan-out 并行）
抽取能力  各步 LLM 抽取器 (prompt + structured_output) + 纯 Python 辅助
工具数据  fetcher / actor_config (热加载) / ioc_regex / whitelist
LLM 模型  ChatOpenAI (DeepSeek) + with_structured_output + 重试 + 降级
输出存储  JSON (Pydantic 校验) + 可选 MD + loguru 日志 + output/ 归档
```

## 节点链

```
fetch ──[失败/空/过短]──> export ──> END
  │                        ↑
  └──[成功]──> extract_basic ──> identify_actors
                                    │
                    ┌──[无 actor]────┘
                    │
                    └──[有 actor]──> fan_out_dispatcher
                                        │
                              ┌─[Send: actor1]──> extract_details ─┐
                              ├─[Send: actor2]──> extract_details ─┤  (并行，只抽 IOC)
                              └─[Send: actorN]──> extract_details ─┘
                                                                    │
                                                            aggregate ──> export
```

## 快速开始

### 环境要求

- Python ≥ 3.10
- DeepSeek API Key（[申请地址](https://platform.deepseek.com/)）
- Windows 下建议启用 UTF-8 模式，避免中文编码问题：
  ```powershell
  $env:PYTHONUTF8=1
  ```

### 安装

```bash
# 克隆项目
git clone <repo-url> && cd intel-agent

# 安装（含开发依赖）
pip install -e ".[dev]"

# 可选：Playwright 兜底抓取 JS 渲染页面
# 部分安全博客为 JS 渲染页面，requests+readability 抓不到正文时需要它
pip install -e ".[playwright]" && playwright install chromium
```

### 配置 API Key

方式一：环境变量（推荐）
```bash
export DEEPSEEK_API_KEY="sk-xxxxxxxx"
```

方式二：配置文件
```bash
# 编辑项目根目录 application.yaml，填入 API Key
# 该文件已被 .gitignore 排除，不会提交到仓库
```yaml
deepseek:
  api_key: "sk-xxxxxxxx"
virustotal:
  api_key: "your-vt-key"
otx:
  api_key: "your-otx-key"
```

### 运行

```bash
# 单个报告 URL
python -m intel_agent https://thedfirreport.com/2021/05/12/conti-ransomware/

# 批量处理
python -m intel_agent -f urls.txt

# 直接输入文本（跳过抓取）
python -m intel_agent --text "报告正文..."

# 输出 Markdown 格式
python -m intel_agent <url> --format md

# 同时输出 JSON + Markdown
python -m intel_agent <url> --format both

# 详细日志
python -m intel_agent <url> --verbose

# 输出流程图
python -m intel_agent --mermaid
```

### 断点续跑

- 默认启用 SQLite checkpointer（`checkpoints.db`），同 URL 崩溃后重跑会自动从断点恢复
- 已完成的 URL 再次运行会换新 thread_id 全新执行，不会累积历史错误
- `--no-resume`：强制全新运行，忽略已有断点
- `--no-checkpointer`：完全禁用断点续跑

### 使用注意

1. **Windows 中文编码**：运行前建议 `$env:PYTHONUTF8=1`，避免中文 prompt 导致 `UnicodeEncodeError`
2. **Playwright**：部分安全博客是 JS 渲染页面，`requests+readability` 抓不到正文时需要安装（见上方安装步骤）
3. **API Key**：填入 `application.yaml` 或设置环境变量 `DEEPSEEK_API_KEY`

## 输出格式

### JSON 结构

```json
{
  "report_name": "报告标题",
  "publish_time": "2021-05-12",
  "summary": "报告概述...",
  "targeted_industries": ["政府", "金融"],
  "targeted_countries": ["美国"],
  "threator": [
    {
      "actor_id": "conti",
      "name": "Conti",
      "theme": "恶意代码家族",
      "aliases_matched": ["Conti ransomware"],
      "is_new_org": false,
      "iocs": [
        {
          "value": "192.168.1.100",
          "type": "IPv4",
          "threat_level": "恶意",
          "tags": ["C2"],
          "context": "C2 服务器地址"
        }
      ],
      "tools": [
        {
          "name": "Cobalt Strike",
          "category": "RAT",
          "description": "..."
        }
      ],
      "vulnerabilities": [
        {
          "cve_id": "CVE-2021-34527",
          "name": "PrintNightmare",
          "description": "..."
        }
      ],
      "ttps": [
        {
          "technique_id": "T1566.001",
          "technique_name": "鱼叉式钓鱼附件",
          "tactic": "初始访问",
          "description": "..."
        }
      ]
    }
  ],
  "new_org_flags": [
    "UnknownGroup 可能是新组织，建议核实后更新攻击组织档案库"
  ],
  "errors": []
}
```

### 异常输出

```json
{
  "error": "HTTP 错误: 404 Client Error",
  "url": "https://example.com/404",
  "errors": []
}
```

## 项目结构

```
intel-agent/
├── config/
│   ├── actors.yaml              # 攻击者档案（可热加载，无需重启）
│   └── whitelist.yaml           # IOC 白名单（云/CDN/安全厂商/私有IP）
│
├── src/intel_agent/
│   ├── cli.py                   # CLI 入口 + 断点续跑
│   ├── graph.py                 # LangGraph 编排（节点+边+router+fan-out）
│   ├── state.py                 # ExtractionState + reducer
│   ├── schemas.py               # Pydantic 模型（单一真相源）
│   ├── llm/
│   │   ├── client.py            # DeepSeek + structured_output + 重试 + 降级
│   │   └── prompts.py           # Prompt 模板（集中管理）
│   ├── nodes/
│   │   ├── fetch.py             # 抓取（requests+readability + Playwright 兜底）
│   │   ├── basic.py             # 基础信息抽取
│   │   ├── actors.py            # 攻击者识别（LLM 直接识别 + 配置交叉比对 + 新组织标记）
│   │   ├── extract_details.py   # 单 actor IOC 抽取（fan-out 并行）
│   │   ├── ioc.py               # IOC 正则召回 + 白名单过滤 + LLM 判级
│   │   └── aggregate.py         # 聚合 + 校验 + 去重 + 补缺省
│   ├── tools/
│   │   ├── ioc_regex.py         # 8 类 IOC 正则
│   │   ├── whitelist.py         # 白名单过滤
│   │   └── actor_config.py      # 攻击者配置 + 热加载
│   └── output/
│       ├── exporter.py          # JSON / Markdown 导出 + 归档
│       └── logging.py           # loguru 日志
│
├── tests/
│   ├── test_ioc_regex.py
│   └── test_actor_config.py
│
├── pyproject.toml
├── application.yaml            # API Key 配置文件（不提交）
└── README.md
```

## 核心设计原则

| 原则 | 说明 |
|------|------|
| **固定流水线，不用 ReAct** | 步骤是需求钉死的"分步抽取"，LangGraph 手工声明全图，LLM 只做抽取不做决策 |
| **早退/跳过是纯 Python 条件边** | 每个 gating 点是纯 Python router 函数检查结构化字段，不把结果丢给 LLM 判走向 |
| **三种失败处理分开** | 早退（跳过下游）、重试（tenacity 原地重跑）、降级（带部分结果继续），不混写 |
| **LLM 产信号，代码做路由** | LLM 的 structured_output 多返回 confidence 等字段，代码用阈值路由 |
| **Pydantic schema 是单一真相源** | `schemas.py` 同时服务 structured_output + 校验 + 导出 + 设计说明书 Schema |
| **正则召回 + LLM 判级，白名单前置** | 正则管格式召回，LLM 管语义判级，白名单在 LLM 前过滤良性资产 |
| **配置驱动 + 热加载** | 攻击者/白名单全部配置化；actors.yaml 支持 mtime 热加载，运营改档案不重启 |
| **LLM 出全，代码兜底** | tools/vulns/ttps 由 LLM 一次抽取（含 ATT&CK 编号）；配置交叉比对识别已知/新组织 |

## 能力矩阵

| 能力 | 实现方式 |
|------|----------|
| 报告抓取 | requests + readability-lxml 为主，Playwright 兜底 JS 渲染页面 |
| 基础信息抽取 | LLM 抽 report_name / publish_time / summary / industries / countries |
| 攻击者识别 | LLM 直接从报告识别攻击主体 + 判 theme + 抽 tools/vulns/ttps → 配置交叉比对 → 新组织标记 |
| IOC 抽取 | LLM 从报告中抽取每个攻击者关联的 IOC，判 type / threat_level / tags（fan-out 并行） |
| ATT&CK 映射 | LLM 直接输出 technique_id / technique_name / tactic（一步到位） |
| 多 actor 并行 | LangGraph Send API fan-out + map-reduce |
| 早退短路 | 抓取失败/空正文/无攻击者 → 直奔 export |
| 断点续跑 | SQLite checkpointer，同 URL 二次 invoke 从断点继续 |
| 重试降级 | tenacity 指数退避重试；LLM 不可用时正则+配置仍产出部分字段 |
| 配置热加载 | actors.yaml 基于 mtime 轮询，运营改档案无需重启 |
| 输出格式 | JSON（Pydantic 校验）+ Markdown + 按日期归档 |

## IOC 类型覆盖

| 类型 | 正则模式 | 示例 |
|------|----------|------|
| IPv4 | 标准 IPv4 | `192.168.1.1` |
| IPv6 | 完整/缩写格式 | `2001:db8::1` |
| Domain | 含子域名 | `evil.example.com` |
| URL | http/https/ftp | `https://evil.com/payload` |
| MD5 | 32 位 hex | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 位 hex | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 位 hex | `e3b0c44298fc1c149afbf4c8996fb924...` |
| FilePath | Windows/Unix | `C:\Windows\System32\malware.dll` |
| Registry | HKLM/HKCU 等 | `HKLM\Software\Microsoft\...` |
| Email | 标准邮箱 | `phishing@evil.com` |

## 威胁等级

| 等级 | 含义 |
|------|------|
| `恶意` | 报告明确关联到恶意行为 |
| `可疑` | 有可疑特征但未明确确认 |
| `未知` | 无法确定（缺省值） |
| `白名单` | 确认为良性/已知合法资产 |

## 运行测试

```bash
pytest tests/ -v
```

## 验证清单

- [x] `python -m intel_agent <url>` 输出经 Pydantic 校验的合法 JSON
- [x] `python -m intel_agent --mermaid` 输出 Mermaid 流程图
- [x] 非法/404 URL：输出 `{"error","url"}`，不崩溃，批量不中断
- [x] 清空 `DEEPSEEK_API_KEY`：降级产出部分字段 + 告警
- [x] 运行中改 `actors.yaml` 新增组织：热加载后下次抽取即识别
- [x] 多 actor 报告：fan-out 并行，details 不丢失（reducer 正确）
- [x] 崩溃续跑：同 `thread_id` 二次 invoke 从断点继续；已完成任务自动换新 thread_id 重新开始
- [x] 纯 Python 工具层（ioc_regex / actor_config）测试全部通过
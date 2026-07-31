"""
Prompt 模板集中管理 — 各抽取步骤的 system/human prompt

约束：集中于此，不散落节点。
prompt 内复述关键字段口径（type/threat_level 取值）。
"""

from langchain_core.prompts import ChatPromptTemplate

# ============================================================
# 1. 基础信息抽取
# ============================================================

BASIC_INFO_SYSTEM = """你是一个专业的威胁情报分析师。请从以下安全报告中提取基础信息。

要求：
- report_name: 报告的原始标题。如果无法确定，请根据报告内容生成一个概括性标题。
- publish_time: 发布时间，格式必须为 YYYY-MM-DD。如果报告没有明确时间，请使用报告描述的事件时间。如果仍然无法确定，填"未知"。
- summary: 报告概述，简要描述报告的主要内容（谁攻击了谁、用什么方法、造成什么影响），不超过 300 字。
- targeted_industries: 受攻击/影响的行业列表，如 ["政府", "金融", "能源"]。如果无法确定，返回空列表。
- targeted_countries: 涉及的国家/地区列表，如 ["中国", "美国"]。如果无法确定，返回空列表。
- confidence: 你对本次抽取的置信度（0.0-1.0）。如果报告信息充分、明确，给高分；如果信息模糊，给低分。"""

BASIC_INFO_HUMAN = "报告内容：\n{report_text}"

BASIC_INFO_PROMPT = ChatPromptTemplate.from_messages([
    ("system", BASIC_INFO_SYSTEM),
    ("user", BASIC_INFO_HUMAN),
])

# ============================================================
# 2. 攻击者识别（LLM 直接从报告中识别所有攻击者）
# ============================================================

ACTOR_CONFIRM_SYSTEM = """你是一个威胁情报分析师。请从以下安全报告中识别所有攻击者（威胁行为者/恶意代码家族）。

对每个识别到的攻击者，提取以下信息：

1. name: 攻击者名称（如 "APT28"、"Conti"、"Emotet"）
2. theme: 攻击者类型，必须为以下之一：
   - "APT": 国家级/高级持续性威胁组织
   - "恶意代码家族": 恶意软件/代码家族
   - "未知": 无法确定类型
3. tools（工具/恶意软件）：
   - name: 工具/恶意软件名称
   - category: 分类（RAT / Downloader / Dropper / Exploit Kit / 后门 / 勒索软件 / 正常工具）
   - description: 使用描述
4. vulnerabilities（漏洞）：
   - cve_id: CVE 编号（如 "CVE-2021-34527"），没有则填 null
   - name: 漏洞名称（如 "PrintNightmare"）
   - description: 利用描述
5. ttps（ATT&CK 技战术）：
   - technique_id: ATT&CK 技术编号（如 "T1566.001"、"T1059"）
   - technique_name: 技术名称（如 "鱼叉式钓鱼附件"、"PowerShell"）
   - tactic: 所属战术（如 "初始访问"、"执行"、"持久化"、"权限提升"、"防御规避"、"凭证访问"、"发现"、"横向移动"、"收集"、"命令与控制"、"数据渗出"、"影响"）
   - description: 该技术在报告中的具体表现

重要规则：
- 只识别本报告实际描述的、作为攻击方的组织，报告中仅被引用/提及/关联的组织不算
- 一个报告可以有多个攻击主体
- 只提取报告中明确提到的内容，不要凭空编造
- 如果某项没有信息，返回空列表"""

ACTOR_CONFIRM_HUMAN = "报告内容：\n{report_text}"

ACTOR_CONFIRM_PROMPT = ChatPromptTemplate.from_messages([
    ("system", ACTOR_CONFIRM_SYSTEM),
    ("user", ACTOR_CONFIRM_HUMAN),
])

# ============================================================
# 3. 单 Actor IOC 抽取
# ============================================================

ACTOR_DETAIL_SYSTEM = """你是一个威胁情报分析师。请从报告中提取以下攻击者关联的 IOC（失陷指标）。

要提取的攻击者：{actor_name}

IOC 要求：
- value: IOC 值，如 "192.168.1.1"、"d41d8cd98f00b204e9800998ecf8427e、"c2.com""
- type: IOC 类型，必须为以下之一：IP/Domain/Email/URL/Hash/CVE/TTP
- threat_level: 威胁等级，必须为以下之一：恶意, 可疑, 未知, 白名单。必填，无法确定时填"未知"
- tags: 附加标签列表，如 ["C2", "Downloader", "Phishing", "Dropper"]
- context: 该 IOC 在报告中的上下文说明，如果上下文无意义可以不添加。

注意：
- 只提取报告中明确提到的、与 {actor_name} 关联的 IOC
- 不要凭空编造
- 如果报告中该攻击者没有明确 IOC，返回空列表"""

ACTOR_DETAIL_HUMAN = "报告内容：\n{report_text}\n\n要提取的攻击者：{actor_name}"

ACTOR_DETAIL_PROMPT = ChatPromptTemplate.from_messages([
    ("system", ACTOR_DETAIL_SYSTEM),
    ("user", ACTOR_DETAIL_HUMAN),
])

# ============================================================
# 4. IOC 判级（对正则候选做语义分析）
# ============================================================

IOC_CLASSIFY_SYSTEM = """你是一个威胁情报分析师。请对以下 IOC 候选进行语义分析。

候选 IOC 列表：
{ioc_candidates}

报告上下文摘要：
{context}

对每个候选 IOC：
- type: 确认其类型（IPv4/IPv6/Domain/URL/MD5/SHA1/SHA256/FilePath/Registry/Email）
- threat_level: 判断威胁等级，必填：
  - "恶意": 报告明确关联到恶意行为
  - "可疑": 有可疑特征但未明确确认
  - "未知": 无法确定
  - "白名单": 确认为良性/已知合法资产
- tags: 附加标签列表，如 ["C2", "Phishing", "Downloader", "Dropper", "Scanner"]
- context: 该 IOC 在报告中的相关上下文

注意：只返回报告中实际出现的 IOC，不要编造。"""

IOC_CLASSIFY_HUMAN = "报告内容：\n{report_text}"

IOC_CLASSIFY_PROMPT = ChatPromptTemplate.from_messages([
    ("system", IOC_CLASSIFY_SYSTEM),
    ("user", IOC_CLASSIFY_HUMAN),
])
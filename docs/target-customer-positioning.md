# iSecOps Hub Target Customer and Product Positioning

## 1. Positioning Statement

iSecOps Hub is an AI-native security operations hub for mid-to-large organizations with high security responsibility, limited budgets, and small security teams.

iSecOps Hub 面向安全责任重大、业务系统复杂、合规压力明显，但安全团队人员有限、预算有限、运营能力不足的中大型组织。

核心定位：按照大客户复杂安全运营要求设计能力上限，按照中大型客户的小团队、轻量化、可交付要求设计落地方式。

## 2. Target Customer

我们的核心客户不是：

- 已经拥有成熟 SOC 团队的超级大客户；
- 可以通过堆人、堆平台、堆定制解决问题的超大型组织；
- 完全没有安全建设基础的小微客户。

我们的核心客户是安全责任重、预算有限、人员不足，但已经承担真实安全运营压力的中大型组织，通常具备以下特征：

- 已经有一定安全产品建设；
- 有合规和安全责任；
- 有领导汇报和事件闭环压力；
- 告警不少但缺少持续研判；
- 设备不少但缺少统一运营；
- 人员少、经验不稳定；
- 预算有限，但安全不能出事的中大型组织。

典型客户包括：

- 区县级单位；
- 地市级单位；
- 高校；
- 医院；
- 制造业集团；
- 区域金融机构；
- 能源 / 交通 / 水务等行业单位；
- 大型企业分支机构；
- MSS / MDR 服务交付团队。

## 3. Strategic Principle

以大客户复杂场景为能力上限，以中大型客户轻量落地为交付下限。

能力上，iSecOps Hub 参考大客户多系统、多角色、多流程、多审计、多厂商、多场景的复杂安全运营要求，确保产品架构能够承载严肃安全运营所需的证据、事实、研判、协同、通知、事件、报告和审计能力。

落地上，iSecOps Hub 避免重型 SIEM 化，避免完整日志湖，避免复杂部署，避免必须堆人才能用，避免长期项目制重定制。产品应优先通过标准化 Integration Package、证据驱动的研判流程、可复用模板和 AI 辅助能力，让有限团队也能持续运营。

最终形成：大客户级能力 + 中大型客户可承受成本 + 小团队可运营体验。

## 4. Customer Pain Points

目标客户的典型痛点包括：

- 安全设备不少，但没有真正运营起来；
- 告警很多，但缺少持续研判；
- 安全人员少，经验不稳定；
- 误报、漏报、重复告警消耗精力；
- 事件确认依赖个人经验；
- 领导需要结果，但过程缺少证据；
- 合规要求有流程、有记录、有报告；
- MDR/MSS 服务交付难以标准化；
- 安全事件难以复盘和沉淀。

## 5. Product Value Proposition

iSecOps Hub 不是替客户再增加一个安全设备，而是帮助客户把已有安全能力真正运营起来。

产品价值包括：

- 多厂商 Integration Package 快速接入客户已有安全产品；
- Evidence Event / Evidence Item 让告警变成可引用证据；
- Fact Ledger 让判断有依据；
- Analysis Case 让小团队也能标准化研判；
- AI Assistant 辅助总结、归因、解释、建议和报告；
- Notification / Incident / Report 形成运营闭环；
- Template / Playbook 把专家经验产品化；
- 本地化部署和审计能力适配政企客户。

## 6. What We Are Not

iSecOps Hub should not be positioned as any of the following:

- Not a full SIEM.
- Not a full raw log lake.
- Not a traditional SOAR that starts from automatic remediation.
- Not another XDR competing with every vendor.
- Not a generic AI chatbot.
- Not a product only for super-enterprise SOC teams.
- Not a tool that requires a large team to operate.

我们不做另一个重型态势感知/日志湖，不做一开始就自动封禁隔离的高风险 SOAR，不做只能靠大团队维护的大而全平台。

## 7. Product Design Implications

这个定位要求产品路线优先服务“可接入、可研判、可闭环、可交付”的安全运营能力。

优先做：

- Integration Runtime；
- Integration Package Registry；
- TDA / 明御APT / 更多厂商包化接入；
- Evidence / Fact Ledger；
- Analysis Case；
- AI-assisted triage；
- Notification / Incident / Report；
- SOC Work Queue future；
- Playbook / Response Approval future。

不优先做：

- 大规模原始日志存储；
- 全量 SIEM 查询语言；
- 大而全 SOAR 自动处置；
- 重型大屏优先；
- 一厂商生态锁定；
- 依赖大量驻场人员的项目制功能。

## 8. Positioning Against Existing Categories

iSecOps Hub 不应该直接宣称自己是 SIEM、XDR、SOAR 或普通 AI SOC。

建议定位：AI-Native Security Operations Hub。

中文定位：AI 原生安全运营中枢。

与既有品类的关系：

- SIEM 偏日志采集、检索、关联；
- XDR 偏原厂检测与响应生态；
- SOAR 偏编排和处置自动化；
- MDR/MSS 偏服务交付；
- iSecOps Hub 的定位是把多厂商安全产品、证据、事实、研判、通知、事件和报告串成可运营闭环。

## 9. Reusable Writing Module

### One-sentence Version

iSecOps Hub 是面向安全人员有限的中大型组织打造的 AI 原生安全运营中枢，按照大客户复杂安全运营要求设计，通过轻量集成、证据驱动研判和人机协同工作流，帮助小团队完成高质量安全事件确认、通知、升级、报告和复盘。

### Short Version

iSecOps Hub 是面向安全责任重大、预算有限、人员不足的中大型组织打造的 AI 原生安全运营中枢。它不是替客户再增加一个安全设备，而是通过多厂商轻量集成、证据驱动研判、Fact Ledger、Analysis Case 和 AI Assistant，把已有安全产品、告警、证据、通知、事件和报告串成可运营闭环。iSecOps Hub 按照大客户复杂安全运营要求设计能力上限，但按照中大型客户小团队、轻量化、可交付的方式落地，帮助客户用可承受成本获得更稳定、更标准化的安全运营能力。

### Long Version

iSecOps Hub 是面向安全责任重大、业务系统复杂、合规压力明显，但安全团队人员有限、预算有限、运营能力不足的中大型组织打造的 AI 原生安全运营中枢。它关注的不是再建设一个重型平台，也不是替代客户已经采购的防火墙、EDR、NDR、APT、WAF、态势感知或其他安全设备，而是帮助客户把已有安全能力真正运营起来。

许多中大型组织已经部署了不少安全产品，也能产生大量告警和日志，但真正困难的是持续研判、证据沉淀、事件闭环、领导汇报和合规留痕。安全团队常常人数有限，经验不稳定，既要处理误报、漏报和重复告警，又要在安全事件发生时给出可解释、可追溯、可复盘的判断。传统大客户 SOC 建设往往依赖大量人员、平台堆叠、长期项目定制和复杂部署，这对中大型客户来说成本高、周期长、落地难。

iSecOps Hub 的核心原则是：以大客户复杂场景为能力上限，以中大型客户轻量落地为交付下限。产品在能力设计上参考大客户多系统、多角色、多流程、多审计、多厂商、多场景的安全运营要求；在落地方式上坚持轻量集成、证据驱动、人机协同和模板化交付，避免重型 SIEM 化、完整日志湖和一开始就自动处置的高风险 SOAR 路线。

通过 Integration Package 快速接入多厂商安全产品，通过 Evidence Event / Evidence Item 把告警转化为可引用证据，通过 Fact Ledger 记录判断依据，通过 Analysis Case 标准化研判流程，通过 AI Assistant 辅助总结、归因、解释、建议和报告，再通过 Notification、Incident 和 Report 形成闭环，iSecOps Hub 帮助小团队获得接近专业 SOC 的运营能力。它的目标不是制造更多系统负担，而是让有限预算和有限人员的组织，也能把安全运营做得更清楚、更稳定、更可交付。

## 10. Tagline Options

- 让小团队具备接近专业 SOC 的运营能力。
- 把已有安全产品真正运营起来。
- 面向中大型组织的 AI 安全运营中枢。
- 多厂商接入、证据驱动、人机协同。
- 不是替代安全设备，而是激活安全运营。
- 大客户级能力，中大型客户可落地。
- 用 AI 和证据链提升安全运营确定性。
- 让告警走向证据，让事件形成闭环。
- 为有限安全团队打造可持续运营能力。
- 轻量集成现有设备，标准化交付安全运营。
- 面向政企和行业客户的 AI 原生安全运营中枢。
- 让安全研判有证据、可协同、能复盘。

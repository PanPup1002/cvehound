# cvehound
CVE目标获取
- 输入：CVE ID
- 输出：经过硬排除和质量评分的有效目标列表
- 依赖：fofa-mcp, nvd-mcp, httpx, cdncheck, wafw00f

## 产出定位

**给人工核验用的目标清单，不是攻击清单。** 所有输出围绕
「让用户快速判断该验证哪个、怎么验证」展开。

## 目录

| 路径 | 用途 |
|------|------|
| `.claude/skills/cve-targets/SKILL.md` | 主工作流（CVE ID → 目标清单） |
| `.claude/agents/cve-recon.md` | 情报解析 + FOFA 搜索 + 探活 Subagent |
| `.claude/hooks/block-dangerous.py` | 危险命令拦截（PreToolUse） |
| `.claude/hooks/audit-log.py` | 操作审计（PreToolUse） |
| `tools/score.py` | 质量评分，产出 json/txt/csv 三件套 |
| `tools/version_compare.py` | 版本比较 + NVD 影响区间提取 |
| `tools/probe_inputs.py` | 探活输入生成（域名优先；含 cdncheck 裸主机文件；可分层抽样） |
| `tools/alive_filter.py` | 用 httpx 探活结果过滤 URL（只留存活主机，供 wafw00f） |
| `tools/gate.py` | 可验证性闸门：candidates / census / sampled / blocked |
| `tools/version_probe.py` | 主动版本探测（只读 GET；产品端点表 + 通用头） |
| `tools/version_probes.json` | 产品 → 版本端点模板 |
| `tools/prefilter.py` | 评分预排名，输出 top-N URL/主机（供 WAF/CDN 探测） |
| `tools/waf_batch.py` | wafw00f 分批执行 + 合并（防 OOM/超长单进程） |
| `tools/census.py` | census 模式资产普查（未探活、未验证） |
| `tools/fofa_cache.py` | FOFA 导出缓存（避免重复消耗配额） |
| `tools/run_state.py` | 运行清单与断点续跑（阶段产物 sha256） |
| `tools/scope.py` | 可选授权范围 allowlist（探活+评分双侧强制） |
| `tools/preflight.py` | 启动前环境检查（preflight=OK / FAIL） |
| `tools/app_rules.json` | 产品名 → FOFA app 规则名映射（自积累） |
| `tools/exclude_keywords.json` | org 硬排除词表 |
| `tools/test_regression.py` | 评分/版本/排除逻辑回归用例 |
| `tools/test_hook.py` | 拦截器回归用例 |

## 环境依赖（本机实测配置）

| 工具 | 路径 | 版本 |
|------|------|------|
| python | `...\Programs\Python\Python311\python.exe` | 3.11.2 |
| httpx | `D:\Environment\GOPATH\bin\httpx.exe` | v1.12.0 |
| cdncheck | `D:\Environment\GOPATH\bin\cdncheck.exe` | v1.3.1 |
| wafw00f | `...\Programs\Python\Python311\Scripts\wafw00f.exe` | v2.4.2 |
| fofa-mcp (MCP) | `npx fofa-mcp@<版本>` | 0.6.2 |
| nvd (MCP) | `npx @cyanheads/nist-nvd-mcp-server@<版本>` | 0.3.1 |

> **两个 MCP server 必须按上述版本号固定**（`claude mcp add ... -- npx <包>@<版本>`）。
> `npx` 裸包名会拉最新，上游改工具参数名会让 agent 静默失效——
> 实测 `nvd_get_cve` 的参数由 `cveId` 变成了 `cveIds`。
> 详见 DEPLOY.md 第 4 步。

> 版本号需要两台机器保持一致，否则输出字段差异会导致 score.py 解析失败。
> **D:\Environment\GOPATH\bin 必须排在任何含 Python 版 httpx.exe 的目录之前**
> （如 Python311\Scripts——其中的 httpx.exe 是 Python 包，会遮蔽 Go 版 httpx）。
> Windows 先解析机器级 PATH 再解析用户级，只在用户级排前面没用；
> 本机已把 D:\Environment\GOPATH\bin 前置到机器级 PATH 最前。`tools/preflight.py` 会自动检测。
>
> Go 布局（不占 C 盘）：SDK 本体 `D:\Environment\GO`（机器级 PATH），
> `GOPATH` / `GOCACHE` 用户级环境变量指向 `D:\Environment\GOPATH` /
> `D:\Environment\GOCACHE`。**升级 Go 不要用 winget**（会装回
> `C:\Program Files\Go`），改用官方 zip 解压覆盖 `D:\Environment\GO`。

`FOFA_API_KEY` 走环境变量继承，**不写入任何配置文件**。

## 已知限制

- **audit.log 记录的是调用意图（`phase: attempt`），不是执行结果。**
  要看执行结果需另加 PostToolUse hook。之所以挂在 PreToolUse：
  实测 PostToolUse 看不到失败命令（非零退出不触发）和被拦截命令
  （调用根本没执行），而这两类恰恰是审计最该留痕的。
- **Server 头版本采信依赖白名单**（`SERVER_HEADER_PRODUCTS`）。
  白名单内直接采信，白名单外一律不采信。代价：`product="Apache Tomcat"`
  配 Server 头 `"Apache-Coyote/1.1"` 会取到 `1.1`（Coyote 版本）。
  这是白名单"对产品授权、不看 Server 头内容"的固有取舍，已知不修。
- **框架类 / 库类 CVE 通常拿不到版本**，`version_status` 会全是 `unknown`。
  这是数据可得性问题（版本不在 HTTP 响应里），不是流程缺陷。
  合理产出就是 unknown 候选池，不应强求 `affected`。
  候选池能否越过 40 分门槛取决于标题证据：FOFA 标题显式含产品名的目标
  （如「系统登录 · ThinkAdmin」）拿到 +30+20=50 进入 `needs_verification`；
  标题不含产品名且无其他证据的仍被门槛挡住（保守保留，宁缺勿滥）。
- **cdncheck 有三个必踩的坑**：① **进程会读 stdin，本环境 stdin 永不 EOF
  → 静默挂死**（与 httpx 同源），命令末尾必须加 `< /dev/null`；② 输入必须
  裸主机名（`host:port` 静默查不到任何结果）；③ 默认解析器
  （1.0.0.1/1.1.1.1）不可达，需 `-r 'doh:https://dns.alidns.com/dns-query'`，
  公共 UDP:53 实测时通时断。
  坑①最隐蔽——进程不报错、不退出、输出为空，易被当成"目标多跑得慢"。
  实测 212 主机：不加 `< /dev/null` 21+ 分钟只出 2 条被迫终止，加了 **7 秒
  正常退出**。此前记的「30 目标挂死」在 212 目标下复现，根因就是坑①。
  `score.py` 仍对空 cdn 文件容错，不阻塞主流程。
- **`body` 字段被 FOFA 账户等级禁用**（`[820001]`），
  因此 score.py 的评分不含 body 匹配信号；`body=` 作为**查询条件**仍可用。
- **FOFA 限速约 1 请求 / 30-60 秒**，并行调用必撞 `[45012]`。
  agent 侧必须串行并 `sleep 60`。
- **`unknown` 永远不等于 `affected`。** 判断不了就保留并降序，
  绝不因为"没版本"而放行到高分。

## 评分模型与授权范围

### 证据独立性（v2）

`match_score` 满分 clamp 到 100，只有独立证据才能拿高分：

| 分值 | 证据 |
|---:|---|
| +30 | FOFA `app=` / `cert=` / `header=` 指纹引擎命中（强 cohort） |
| +40 | httpx `tech[]` 命中产品（强独立） |
| +30 | `server` / `X-Powered-By` 命中产品（强独立） |
| +25 | 有可靠版本号（tech/server/version_probe） |
| +25 | `version_status == "affected"` |
| +10 | 标题命中产品（弱） |
| 0 | 仅"标题非空"；或 `title="X"` 查询的标题命中（查询自证） |

`title="X"` 类指纹不再让每条结果自动拿 50 分；纯标题命中会被 40 分门槛挡掉。

负向词（`tools/fingerprint_rules.json`）：`blog/docs/tutorial/marketing/news` 等按
hard/soft/gray 扣分；**hard 词命中标题直接把 `confidence_tier` 封顶为 C**。

### 交付分级

`confidence_tier`：**A** = 版本命中；**B** = 强指纹但版本未知；
**C** = 弱证据（默认只计数，不进主清单）。

### 分类

`likely_affected`（≥80 且 affected）/ `probable`（≥60）/
`needs_verification`（≥40，默认门槛）/ `rejected`（<40）。
`unknown` 版本永远升不到 `likely_affected`。

### 闸门与探测成本

- `tools/gate.py` 在 NVD 情报后判定流程强度：
  - **默认 candidates**：执行 httpx 探活 + 版本探测 + 评分；
  - `version_observable=false` 仍会探活与评分，只是 `ceiling=B`、
    `affected` 不可达，输出 **tier B 候选池**；
  - **census** 仅在显式 `run_mode=census` 时启用，只做 FOFA 统计/导出；
  - `blocked` 仅在产品信息缺失时出现。
- 产品不在版本端点表里时，`version_probe` 会尝试通用规则
  （Server 头、generator meta、页面中产品名邻近的版本号）。
- WAF/CDN 默认不探测；仅对 `tools/prefilter.py` 选出的 top-N（默认 100）执行。
- 缺失/未测记 `reachability=not_tested`、成本 `null`，**绝不默认 direct**。
- 输出截断默认分层抽样（`--selection stratified`），并写 `*_coverage.json`。

### 授权范围

提供 scope JSON 后（格式见 `tools/scope.py`），探活与评分两侧强制剔除范围外资产；
未提供时不启用。

## 运行

```
python tools/preflight.py          # 启动前环境检查
python tools/test_regression.py    # 评分/版本/排除逻辑回归
python tools/test_hook.py          # 危险命令拦截回归
python tools/score.py --help       # 评分脚本
```

# 部署与迁移指南

本文档用于将 cvehound 项目部署到新机器。

## 环境要求

| 组件 | 版本 | 用途 |
|------|------|------|
| Windows | 10/11 | 目标平台 |
| Python | 3.10+ | score.py / wafw00f |
| Node.js | 18+ | MCP server (npx) |
| Go | 1.20+ | httpx / cdncheck 编译 |
| Claude Code | 最新 | 编排引擎 |

## 迁移步骤

### 1. 解压项目

将 cvehound-migration.zip 解压到目标位置，例如：
C:\Users\<用户名>\Desktop\cvehound

确认解压后包含：
- .claude/（Skill / Subagent / Hook 配置）
- tools/（score.py / version_compare.py / app_rules.json）
- data/（只有 .gitkeep）

### 2. 安装本地工具链

go env -w GOPROXY=https://goproxy.cn,direct
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
python -m pip install wafw00f

验证：
where.exe httpx
where.exe cdncheck
where.exe wafw00f
httpx -version
cdncheck -version
wafw00f --version

注意：
- Go 可用 winget 安装：winget install GoLang.Go
- 本机约定 Go 工具链放 D 盘（不占 C 盘），布局：
  D:\Environment\GO（SDK 本体）、D:\Environment\GOPATH（工具+模块缓存）、
  D:\Environment\GOCACHE（编译缓存）。装完 Go 后按「已知坑 → Go 工具链
  迁移到 D 盘」迁移一次。
- Go 工具装在 D:\Environment\GOPATH\bin\，**必须排在任何含 httpx.exe 的
  目录之前**（如 Python311\Scripts\httpx.exe——那是 Python 的 httpx 包，会遮蔽
  Go 版）。Windows 先解析机器级 PATH 再解析用户级：只在用户级 PATH 里排前面
  没用，要把 D:\Environment\GOPATH\bin 前置到**机器级** PATH 最前（需管理员
  权限）。检查：where.exe httpx 看第一个是不是 D:\Environment\GOPATH\bin；
  或跑 python tools/preflight.py（会检测并给出修复提示）。
- Python 用 python 不用 python3（Windows 上 python3 可能指向 MSYS2）

### 3. 设置 FOFA API Key

在普通 PowerShell 窗口执行：
[Environment]::SetEnvironmentVariable('FOFA_API_KEY','你的key','User')

验证：
[Environment]::GetEnvironmentVariable('FOFA_API_KEY','User')

### 4. 注册 MCP Server

**必须固定版本号**（`@x.y.z`），不要裸写包名——`npx` 默认拉最新，
上游改参数名会让 agent 静默失效（实测：`nvd_get_cve` 的参数从 `cveId`
变成了 `cveIds`，裸装最新版就报 `Unrecognized key: "cveId"`）。

claude mcp add fofa-mcp -- npx fofa-mcp@0.6.2
claude mcp add nvd -- npx @cyanheads/nist-nvd-mcp-server@0.3.1
claude mcp list

`claude mcp list` 里两个都要显示 `✔ Connected`。
升级时**同时**改上面两行的版本号，并按第 2 节的方式复测一次流水线。

注意：
- MCP 只在 Claude Code 启动时加载，注册完必须彻底重启 Claude Code。
- 首次用固定版本时 `npx` 要现下载，冷启动可能超过 Claude Code 的 30s
  连接超时、显示 `✘ Failed to connect`。这不是配置错——先手动
  `npx -y <包>@<版本> --help` 热一次缓存，再 `claude mcp list` 复查即可。
- `claude mcp add` 默认是 **local 作用域**，绑定项目**绝对路径**存在
  `~/.claude.json` 的 `projects["<路径>"].mcpServers` 下。**移动或改名项目
  目录后这两个 server 会失效**（表现为新目录里 `claude mcp list` 看不到它们），
  需在新目录重跑本节命令。要避免这个问题可改用 `.mcp.json` 项目级配置。

### 5. 重启并验证

任务管理器确认所有 claude.exe 和 node.exe 退出，重新启动。

在新会话中：
0. python tools/preflight.py 输出 preflight=OK（常见唯一 FAIL 是
   FOFA_API_KEY 未设置——按第 3 步设置后重启）
1. 列出可用的 mcp__fofa-mcp__* 和 mcp__nvd__* 工具
2. 用 FOFA 搜索 title="登录" 的前 3 条结果
3. 查询 CVE-2021-44228 的 NVD 详情
4. 用 CVE-2020-25540 找目标（跑完整流水线）

## 已知坑

### Python 解释器
统一用 python，不要用 python3。

### httpx 的两个干扰参数
- -duc        关闭启动时的更新检查（联网不通时会挂）
- -auth=false 关闭 PDCP 云端认证（联网不通时会挂）

这两个是 cve-recon.md 里已经在用的参数。

### Windows Defender / 企业 EDR
Go 编译的 exe 可能被误报或隔离。若 httpx / cdncheck 无法启动，
在 Windows 安全中心 → 病毒和威胁防护 → 排除项里添加：
   D:\Environment\GOPATH\bin\httpx.exe
   D:\Environment\GOPATH\bin\cdncheck.exe

注意：杀软拦截的表现是「文件被杀 / 无法启动」，
不是「进程挂着不动」。后者见下面「故障排查」——那是 stdin 问题，加排除没用。

### FOFA 限速
约 1 请求 / 30-60 秒。Agent 内部已 sleep 60，一个 CVE 约 3-8 分钟。

### Go 工具版本必须一致
两台机器的 httpx / cdncheck 版本不一致会导致输出字段差异。
旧机器记录：
httpx -version
cdncheck -version
新机器装完对比，不一致用 go install ...@v1.12.0 指定版本。

### Go 工具链迁移到 D 盘

本机布局（不占 C 盘）：SDK 在 `D:\Environment\GO`，GOPATH 在
`D:\Environment\GOPATH`，GOCACHE 在 `D:\Environment\GOCACHE`。
新机器上装完 Go 后执行一次迁移：

1. 复制 `C:\Program Files\Go` → `D:\Environment\GO`，先验证
   `D:\Environment\GO\bin\go.exe version` 可用再动旧的
2. 移动 `%USERPROFILE%\go` → `D:\Environment\GOPATH`
3. 删除 `%LOCALAPPDATA%\go-build`（纯缓存），新建 `D:\Environment\GOCACHE`
4. 用户级环境变量：`GOPATH=D:\Environment\GOPATH`、
   `GOCACHE=D:\Environment\GOCACHE`、`GOPROXY=https://goproxy.cn,direct`
5. 管理员：删除 `C:\Program Files\Go`；机器级 PATH 移除旧 go\bin 条目，
   把 `D:\Environment\GOPATH\bin;D:\Environment\GO\bin` 前置到最前
6. 验证：`where.exe httpx` 第一个是 `D:\Environment\GOPATH\bin`；
   `python tools/preflight.py` 输出 OK

**升级 Go 不要用 winget**（会装回 `C:\Program Files\Go` 并重建旧 PATH 条目），
改用官方 zip 解压覆盖 `D:\Environment\GO`。

## v2 流程与新增工具

| 工具 | 用途 | 关键默认值 |
|---|---|---|
| `tools/gate.py` | 可验证性闸门 | 版本不可观测 → census |
| `tools/version_probe.py` | 主动版本探测 | 只读 GET；50 目标；每目标 2 条规则 |
| `tools/prefilter.py` | 评分预排名 | top-100 供 WAF/CDN |
| `tools/waf_batch.py` | wafw00f 分批 | 32 条/批；900s/批 |
| `tools/census.py` | census 资产普查 | 未探活、未验证 |
| `tools/fofa_cache.py` | FOFA 导出缓存 | key=query+page+size+fields |
| `tools/run_state.py` | 运行清单/断点续跑 | 阶段产物 sha256 |

`score.py` 新增参数：`--version-probe`、`--selection stratified|top`、
`--skip-reachability`。兼容性：JSON 仍是数组、20 个旧字段保留；
TXT 不变；CSV 前 8 列不变，末尾追加新列。

语义变更：
- **默认执行探活与评分**（candidates）。`version_observable=false` 只把 ceiling
  降到 B，不再跳过 httpx/评分——输出 tier B 候选池。
- **census 仅在显式 `run_mode=census` 时启用**，只做 FOFA 统计/导出。
- **缺失或未测 WAF/CDN → `reachability=not_tested`、成本 null**，
  不再静默当成 `direct`。需要旧行为时显式传 `--skip-reachability` 也不会伪造 direct。
- **`title=` 查询的标题命中不再计分**；纯标题命中会被 40 分门槛挡掉。
- 负向词表 `tools/fingerprint_rules.json`：hard 词命中标题会把 tier 封顶为 C。
- 输出截断默认分层抽样；覆盖率写入 `*_coverage.json`。
- **census 模式的产出**：`*_census.json/.csv`（只在显式 `run_mode=census` 时生成），
  报告明确写「0 条可验证候选」。
- 默认大多数 CVE 会走 census。要强制完整流程：在 `tools/version_probes.json`
  增加该产品的版本端点规则，或在 context.json 设 `"run_mode": "candidates"`。

主动版本探测的安全边界（硬编码）：只发 GET、无认证、无 payload；
遵守 `--scope`；`--max-targets`/`--max-requests` 限量；可用 `--dry-run` 先看计划。

FOFA 账户无 `body` 字段导出权限（`[820001]`）：查询条件可继续用 `body=`，
但导出 `fields` 必须移除 `body`。本方案以 version_probe 和独立指纹降低依赖。

## 项目结构

输入: CVE ID
  ↓
[Skill: cve-targets] 触发
  ↓
[Subagent: cve-recon]
  ├─ NVD 查 CVE → context.json
  ├─ gate.py 可验证性闸门
  │    ├─ census：只做 FOFA 统计/导出 → census.json/.csv
  │    └─ candidates：继续
  ├─ 查 app_rules.json → 确定 FOFA 规则名
  ├─ fofa_stats 预检 → fofa_export 导出 raw.json（含 country）
  ├─ httpx 探活 → version_probe 主动版本探测
  ├─ prefilter top-N → （按需）cdncheck / waf_batch
  └─ score.py 评分 → targets.json / .txt / .csv / coverage.json
  ↓
输出: 目标清单（tier A/B/C）+ top 10 + 覆盖率

## 常用命令

在 Claude Code 会话中：
用 CVE-2021-44228 找目标
用 CVE-2020-25540 找目标，只返回 match_score 最高的 5 条
显示 data/CVE-2021-44228_targets.json

## data/ 说明

data/ 下所有文件都是运行时产物，可以随时删除。
新机器上 data/ 是空的（只有 .gitkeep），第一次跑 CVE 会自动生成。

## 清理方法

cd C:\Users\<用户名>\Desktop\cvehound
Get-ChildItem data\ -Force | Where-Object { $_.Name -ne '.gitkeep' } | Remove-Item -Force -Recurse

## 故障排查

httpx 卡死无输出（最常见）：
- 真因：httpx 会顺带读 stdin 当输入源，某些环境下 stdin 永不 EOF → 静默挂死。
- 解法：命令末尾加 < /dev/null。参考 .claude/agents/cve-recon.md Step 5b。
- httpx 还会在启动时联网检查更新，加 -duc 关闭。

cdncheck 卡死不动（最常见，且最隐蔽）：
- **真因：cdncheck 会顺带读 stdin 当输入源，本环境 stdin 永不 EOF → 静默挂死。**
  与上面 httpx 那条同源。表现是进程不报错、不退出、输出文件长期为空，
  极易被误判成"目标太多跑得慢"而干等。
- **解法：命令末尾加 `< /dev/null`。** 实测同一份 212 主机的输入：
  不加 → 21+ 分钟只出 2 条、最后只能手动终止；加了 → **7 秒正常退出**。
  cve-recon.md Step 5c 已带该参数。
- 2026-10 复测（无 EDR）：33 目标 ~60s 正常退出。**但 212 目标规模下
  「30 目标挂死」复现了**——根因就是上面这条 stdin 问题，与目标数量、
  解析器、`-resp`/`-cdn`/`-waf` 哪个 flag 都无关（逐个 flag 隔离实测，
  连不加 flag 都挂）。不要再去调 flag 了，先加 `< /dev/null`。

cdncheck 无结果 / 解析失败：
- **输入必须裸主机名**：host:port 输入会静默查不到任何结果。
  用 probe_inputs.py 产出的 _probe_hosts.txt。
- **默认解析器境内不可达**（1.0.0.1/1.1.1.1）：现象是大量 could not resolve
  且极慢。公共 UDP:53（223.5.5.5 等）实测时通时断；用 DoH：
  -r 'doh:https://dns.alidns.com/dns-query'
- score.py 对空 cdn 文件容错，不阻塞主流程。

FOFA 返回 [45012]：
请求速度过快。Agent 内部已 sleep 60，如有并行调用检查 Subagent 逻辑。

Claude Code 看不到 MCP 工具：
- 确认 claude mcp list 显示两个 server 为 connected
- 确认 Claude Code 彻底重启
- 确认 FOFA_API_KEY 在新会话可见

score.py 报 UnicodeDecodeError：
检查 httpx / wafw00f 输出文件编码。当前实现所有 open() 已显式 encoding='utf-8'。

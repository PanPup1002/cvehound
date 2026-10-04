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

claude mcp add fofa-mcp -- npx fofa-mcp
claude mcp add nvd -- npx @cyanheads/nist-nvd-mcp-server
claude mcp list

注意：MCP 只在 Claude Code 启动时加载，注册完必须彻底重启 Claude Code。

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

## 项目结构

输入: CVE ID
  ↓
[Skill: cve-targets] 触发
  ↓
[Subagent: cve-recon]
  ├─ NVD 查 CVE → context.json
  ├─ 查 app_rules.json → 确定 FOFA 规则名
  ├─ fofa_stats 预检 → fofa_export 导出 raw.json
  ├─ httpx / cdncheck / wafw00f 探活
  └─ score.py 评分 → targets.json / .txt / .csv
  ↓
输出: 目标清单 + top 10 表格

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

cdncheck 无结果 / 极慢：
- **输入必须裸主机名**：host:port 输入会静默查不到任何结果。
  用 probe_inputs.py 产出的 _probe_hosts.txt。
- **默认解析器境内不可达**（1.0.0.1/1.1.1.1）：现象是大量 could not resolve
  且极慢。公共 UDP:53（223.5.5.5 等）实测时通时断；用 DoH：
  -r 'doh:https://dns.alidns.com/dns-query'
- 2026-10 复测（无绿盟 EDR，33 目标混公网/拒连）：~60s 正常退出，
  此前「30 目标挂死」未复现。score.py 仍对空 cdn 文件容错，不阻塞主流程。

FOFA 返回 [45012]：
请求速度过快。Agent 内部已 sleep 60，如有并行调用检查 Subagent 逻辑。

Claude Code 看不到 MCP 工具：
- 确认 claude mcp list 显示两个 server 为 connected
- 确认 Claude Code 彻底重启
- 确认 FOFA_API_KEY 在新会话可见

score.py 报 UnicodeDecodeError：
检查 httpx / wafw00f 输出文件编码。当前实现所有 open() 已显式 encoding='utf-8'。

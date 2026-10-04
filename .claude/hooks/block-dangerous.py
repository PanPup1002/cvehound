"""
PreToolUse hook：拦截危险命令。

Claude Code 通过 bash 调用本脚本（Windows 上也是 bash，实测确认），
调用形式见 .claude/settings.json：
    python "$CLAUDE_PROJECT_DIR/.claude/hooks/block-dangerous.py"

stdin 收到 hook JSON（含 tool_name / tool_input / session_id，实测确认）。
命中危险模式时输出 deny 决策阻止该次工具调用。

设计原则：**失败即放行**。任何解析异常都返回 0 不拦截 ——
审计/拦截脚本自身出问题不应该让整个会话不可用。
"""

import json
import re
import sys

# (正则, 人类可读的原因)
DANGEROUS = [
    # ---- Unix ----
    (r'rm\s+-rf\s+/', '递归删除根路径'),
    (r'dd\s+if=/dev/zero', 'dd 写零设备'),
    (r'mkfs\.', '格式化文件系统'),
    (r'>\s*/dev/sd', '直接写块设备'),
    (r':\(\)\s*\{.*\}', 'fork 炸弹'),
    (r'chmod\s+-R\s+777\s+/', '对根路径递归放宽权限'),
    # ---- Windows（本项目的实际运行环境，原清单只覆盖 Unix）----
    (r'\brd\s+/s\s+/q\s+[a-zA-Z]:\\?\s*$', '递归删除盘符根目录'),
    (r'\bdel\s+/[fsq]+\s+/[fsq]+\s+[a-zA-Z]:\\?\s*$', '递归删除盘符根目录'),
    (r'\bformat\s+[a-zA-Z]:', '格式化盘符'),
    (r'Remove-Item\b.*-Recurse.*-Force.*[a-zA-Z]:\\?\s*$', 'PowerShell 递归强删盘符'),
]


def main():
    # 与 audit-log.py 同理：走 buffer + 显式 utf-8，避免 Windows 上
    # sys.stdin 按 cp936 误解码 Claude Code 发来的 UTF-8 JSON。
    try:
        data = json.loads(sys.stdin.buffer.read().decode('utf-8', 'replace'))
    except Exception:
        return 0

    cmd = str((data.get('tool_input') or {}).get('command', ''))
    if not cmd:
        return 0

    for pattern, why in DANGEROUS:
        if re.search(pattern, cmd):
            # ensure_ascii=True：输出纯 ASCII JSON，控制台编码再乱
            # 也能被 Claude Code 正确解析（deny 决策不能因编码丢）
            print(json.dumps({
                'hookSpecificOutput': {
                    'hookEventName': 'PreToolUse',
                    'permissionDecision': 'deny',
                    'permissionDecisionReason': f'命中危险模式（{why}）: {pattern}',
                }
            }, ensure_ascii=True))
            return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())

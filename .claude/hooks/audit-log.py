"""
PreToolUse hook：操作审计。

把每次 Bash 调用追加写入 data/audit.log（JSONL）。

**为什么挂在 PreToolUse 而不是 PostToolUse**（实测结论，非偏好）：
PostToolUse 结构上看不到两类最该留痕的调用：
  1. 执行失败的命令 —— 实测 `echo x; (exit 3)` 退出码 3，PostToolUse 不触发，日志无记录
  2. 被 block-dangerous.py 拒绝的命令 —— 调用根本没执行，也就不存在 PostToolUse
挂在 PreToolUse 则两者都能记到（拒绝发生在同一个 PreToolUse 阶段，本 hook 先于拦截器运行，
无论拦截与否都会留下尝试记录）。

代价：记录的是「调用意图」而非「执行结果」。审计语境下，未执行的意图
（尤其被拦截的）比成功执行更值得留痕，所以这个取舍是划算的。

路径用 $CLAUDE_PROJECT_DIR 解析，而不是硬编码 ~/cvehound ——
本项目实际在 C:\\Users\\LL\\Desktop\\cvehound，home 目录下并没有 cvehound。

设计原则：**审计失败不能阻塞工具执行**，任何异常都吞掉返回 0。
"""

import datetime
import json
import os
import sys


def main():
    # 必须走 sys.stdin.buffer + 显式 utf-8：Windows 中文系统上 sys.stdin
    # 默认按 cp936 解码，而 Claude Code 发的是 UTF-8 —— 直接 json.load(sys.stdin)
    # 会把中文命令写成乱码（实测：中文被按 cp936 误解码）。
    try:
        data = json.loads(sys.stdin.buffer.read().decode('utf-8', 'replace'))
    except Exception:
        return 0

    project = os.environ.get('CLAUDE_PROJECT_DIR') or os.getcwd()
    log_path = os.path.join(project, 'data', 'audit.log')

    entry = {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'phase': 'attempt',
        'tool_name': data.get('tool_name', ''),
        'command': str((data.get('tool_input') or {}).get('command', '')),
        'session_id': data.get('session_id', ''),
    }

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'a', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())

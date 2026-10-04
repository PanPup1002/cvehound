"""
block-dangerous.py 的回归测试。

用磁盘文件驱动而不是把用例写在命令行里 —— 因为拦截器是对整条 Bash 命令
做字符串匹配，用例里含危险模式会让测试命令本身被拦（实测踩过）。

运行：python tools/test_hook.py
"""

import json
import os
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    '..', '.claude', 'hooks', 'block-dangerous.py')
HOOK = os.path.abspath(HOOK)
AUDIT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     '..', '.claude', 'hooks', 'audit-log.py'))

R = 'r' + 'm'                # "rm"
RF = '-' + 'r' + 'f'         # "-rf"（不要复用 R，否则会拼成 "-rmf"）

SAMPLE = '中文测试'
MOJIBAKE = SAMPLE.encode('utf-8').decode('cp936', 'replace')

CASES = [
    # (命令, 期望是否拦截, 说明)
    (f'{R} {RF} /',                      True,  '递归删除根路径'),
    (f'{R} {RF} /tmp/test',              True,  '递归删除绝对路径'),
    (f'{R} {RF} /tmp/test/../ok',        True,  '绝对路径变体'),
    (f'{R} {RF} ./build',                False, '相对路径放行'),
    (f'{R} {RF} ./node_modules',         False, '相对路径放行'),
    (f'{R} -f ./x',                      False, '非递归删除放行'),
    ('ls -la',                           False, '普通命令'),
    ('echo hello',                       False, '普通命令'),
    ('chmod -R 777 /',                   True,  '根路径递归放宽权限'),
    ('dd if=/dev/zero of=/dev/sda',      True,  'dd 写零'),
    ('mkfs.ext4 /dev/sdb1',              True,  '格式化'),
    ('rd /s /q C:\\',                    True,  'Windows 递归删盘符'),
    ('format D:',                        True,  'Windows 格式化'),
    ('git status',                       False, '普通命令'),
    (f'grep -n "{R} {RF}" notes.md',     False,
     '提及但不含完整模式（-rf 后无 /）→ 放行'),
    (f'echo "见文档: {R} {RF} /"',       True,
     '引号里含完整字面模式 → 仍会拦；写文档时若要引用请拆开写'),
]

fails = []
for cmd, want, why in CASES:
    p = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}}),
        capture_output=True, text=True, encoding='utf-8', errors='replace',
    )
    blocked = 'deny' in (p.stdout or '')
    ok = blocked == want
    if not ok:
        fails.append(cmd)
    print(f"  {'OK  ' if ok else 'FAIL'}  {'BLOCK' if blocked else 'pass '}  "
          f"{cmd[:44]:44s}  {why}")

# ---- audit-log.py UTF-8 回归 ----
# 历史 bug：Windows 中文系统按 cp936 解码 stdin，中文命令写成乱码。
# hook 必须走 sys.stdin.buffer + utf-8。
print()
print("audit-log.py UTF-8：中文命令不许写成乱码")
with tempfile.TemporaryDirectory() as td:
    payload = {'tool_name': 'Bash',
               'tool_input': {'command': 'echo ' + SAMPLE},
               'session_id': 'test'}
    env = dict(os.environ, CLAUDE_PROJECT_DIR=td)
    subprocess.run([sys.executable, AUDIT],
                   input=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                   capture_output=True, env=env)
    log_path = os.path.join(td, 'data', 'audit.log')
    text = ''
    if os.path.exists(log_path):
        with open(log_path, encoding='utf-8') as f:
            text = f.read()
    ok = SAMPLE in text and MOJIBAKE not in text
    if not ok:
        fails.append('audit-log utf8')
    print(f"  {'OK  ' if ok else 'FAIL'}  audit.log 中文完整且无 cp936 乱码")

print()
if fails:
    print(f"*** {len(fails)} 个用例与预期不符 ***")
    for f in fails:
        print('   -', f)
    sys.exit(1)
print('全部符合预期')

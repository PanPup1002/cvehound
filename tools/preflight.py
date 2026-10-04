"""
启动前检查（cve-recon Step 0 调用）。

检查项与失败策略：
  1. Python >= 3.10                       不满足 → FAIL
  2. httpx 必须是 ProjectDiscovery Go 版  Python httpx 包 → FAIL（明确识别并提示）
  3. cdncheck / wafw00f 存在              缺失 → FAIL
  4. 工具版本 vs EXPECTED（README 记录）   不一致 → 仅告警；两台机器版本必须一致
  5. FOFA_API_KEY 环境变量                缺失 → FAIL（设置方法见 DEPLOY.md 第 3 步）
  6. data/ 目录可写                       不可写 → FAIL

退出码：0 = 通过（允许告警）；6 = 环境不可用（工具/凭证/目录）。

所有外部命令都带 timeout —— httpx 启动时会联网检查更新，
不加 timeout 会被挂死拖住（实测，-duc 也不保证完全避免）。
本脚本只报告环境事实，不做任何安装/修复动作。
"""

import os
import re
import subprocess
import sys

EXPECTED = {
    'httpx': '1.12.0',
    'cdncheck': '1.3.1',
    'wafw00f': '2.4.2',
}

VER_RE = re.compile(r'(\d+\.\d+\.\d+)')

problems = []
warnings = []


def _run(cmd, timeout=25):
    """返回输出文本；找不到命令返回 None；超时返回 '<<timeout>>'。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return (p.stdout or '') + (p.stderr or '')
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return '<<timeout>>'
    except OSError:
        return None


def _version_of(text):
    m = VER_RE.search(text or '')
    return m.group(1) if m else None


def check_httpx():
    text = _run(['httpx', '-duc', '-auth=false', '-version'])
    if text is None:
        problems.append('httpx 不存在（需要 ProjectDiscovery Go 版；'
                        '安装方法见 DEPLOY.md 第 2 步）')
        return
    if text == '<<timeout>>':
        problems.append('httpx -version 超时挂死（启动联网检查？）')
        return
    low = text.lower()
    if 'projectdiscovery' not in low and 'current version' not in low:
        first = (text.strip().splitlines() or [''])[0][:80]
        problems.append('PATH 上的 httpx 不是 ProjectDiscovery Go 版'
                        f'（疑似 Python httpx 包，输出: {first}）。'
                        '把 D:\\Environment\\GOPATH\\bin 放到 PATH 前面')
        return
    ver = _version_of(text)
    if ver and EXPECTED['httpx'] and ver != EXPECTED['httpx']:
        warnings.append(f'httpx 版本 {ver} != 期望 {EXPECTED["httpx"]}'
                        '（两台机器版本不一致会导致输出字段差异）')
    print(f'[preflight] httpx={ver} OK')


def check_cdncheck():
    text = _run(['cdncheck', '-version'])
    if text is None:
        problems.append('cdncheck 不存在（DEPLOY.md 第 2 步）')
        return
    if text == '<<timeout>>':
        warnings.append('cdncheck -version 超时（进程可能仍可用）')
        return
    ver = _version_of(text)
    if ver and EXPECTED['cdncheck'] and ver != EXPECTED['cdncheck']:
        warnings.append(f'cdncheck 版本 {ver} != 期望 {EXPECTED["cdncheck"]}')
    print(f'[preflight] cdncheck={ver} OK')


def check_wafw00f():
    text = _run(['wafw00f', '--version'])
    if text is None:
        problems.append('wafw00f 不存在（python -m pip install wafw00f）')
        return
    ver = _version_of(text)
    if ver and EXPECTED['wafw00f'] and ver != EXPECTED['wafw00f']:
        warnings.append(f'wafw00f 版本 {ver} != 期望 {EXPECTED["wafw00f"]}')
    print(f'[preflight] wafw00f={ver} OK')


def check_key_and_dirs():
    if os.environ.get('FOFA_API_KEY'):
        print('[preflight] FOFA_API_KEY 已设置')
    else:
        problems.append('FOFA_API_KEY 未设置 —— 按 DEPLOY.md 第 3 步设置后'
                        '重启 Claude Code（MCP 服务读取的是启动时环境变量）')
    data_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'data')
    try:
        os.makedirs(data_dir, exist_ok=True)
        probe = os.path.join(data_dir, '.preflight_write_test')
        with open(probe, 'w', encoding='utf-8') as f:
            f.write('ok')
        os.remove(probe)
        print('[preflight] data/ 可写')
    except OSError as e:
        problems.append(f'data/ 不可写: {e}')


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

    if sys.version_info >= (3, 10):
        print(f'[preflight] python={sys.version.split()[0]} OK')
    else:
        problems.append(f'Python {sys.version.split()[0]} < 3.10')

    check_httpx()
    check_cdncheck()
    check_wafw00f()
    check_key_and_dirs()

    for w in warnings:
        print(f'[warn] {w}')
    for p in problems:
        print(f'[fail] {p}')
    if problems:
        print('preflight=FAIL')
        return 6
    print('preflight=OK' + ('（有告警）' if warnings else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())

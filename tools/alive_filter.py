"""
用 httpx 探活结果过滤 URL 列表，只保留存活主机——供 wafw00f 使用。

为什么需要（实测）：
  wafw00f 对连不上的主机会逐个耗尽连接超时。同一份输入，
  喂 219 个 URL（含 177 个 httpx 已判死的主机）→ >400s 仍未完成；
  只喂 httpx 确认存活的 42 个 → **38s**。
  wafw00f 本就只对能连上的主机输出结果（实测产出是存活集合的子集），
  所以过滤掉死主机**不损失任何数据**，反而因减少干扰提升覆盖率
  （219 输入时漏了 1 台存活主机，过滤后 42 台全出）。

存活判定：httpx jsonl 里 `failed` 不为 true 的记录，取其 `input` 字段
（host:port，与 probe_urls.txt 去掉 scheme 后一致）。

用法：
  python tools/alive_filter.py --httpx data/CVE-XXXX_httpx.jsonl \
      --urls data/CVE-XXXX_probe_urls.txt \
      --output data/CVE-XXXX_waf_input.txt

退出码：0 成功；2 输入缺失/损坏。
"""

import argparse
import json
import os
import re
import sys

_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')


def load_alive(httpx_path):
    """返回 httpx 判活主机的 host:port 集合。"""
    alive = set()
    with open(httpx_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict) or rec.get('failed'):
                continue
            inp = rec.get('input')
            if inp:
                alive.add(str(inp).strip())
    return alive


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='用 httpx 探活结果过滤 URL 列表（只留存活主机，供 wafw00f）')
    ap.add_argument('--httpx', required=True, help='httpx -j 输出的 jsonl')
    ap.add_argument('--urls', required=True, help='待过滤的 URL 列表（scheme://host:port）')
    ap.add_argument('--output', required=True, help='输出的存活 URL 列表')
    args = ap.parse_args(argv)

    try:
        alive = load_alive(args.httpx)
    except FileNotFoundError:
        print(f'[错误] httpx 文件不存在: {args.httpx}', file=sys.stderr)
        return 2
    except OSError as e:
        print(f'[错误] 读取 httpx 文件失败: {e}', file=sys.stderr)
        return 2

    try:
        with open(args.urls, encoding='utf-8') as f:
            urls = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(f'[错误] URL 列表不存在: {args.urls}', file=sys.stderr)
        return 2
    except OSError as e:
        print(f'[错误] 读取 URL 列表失败: {e}', file=sys.stderr)
        return 2

    kept = [u for u in urls if _SCHEME_RE.sub('', u) in alive]

    d = os.path.dirname(os.path.abspath(args.output))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(kept) + ('\n' if kept else ''))

    print(f'urls={len(urls)} alive={len(alive)} kept={len(kept)}')
    print(f'output={os.path.abspath(args.output)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

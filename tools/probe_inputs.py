"""
从 FOFA raw.json 生成探活输入（域名优先，修正虚拟主机错探）。

输出（前缀由 --prefix 指定，如 data/CVE-2021-44228）：
  {prefix}_probe_targets.txt   host:port，给 httpx
  {prefix}_probe_urls.txt      scheme://host:port，给 wafw00f
  {prefix}_probe_hosts.txt     裸主机名（无端口），给 cdncheck ——
                               cdncheck v1.3.1 对 host:port 静默查不到结果：
                               实测 www.fastly.com:443 无输出、裸域名正常命中

为什么域名优先：
  同一个 IP:port 在不同 Host/SNI 下可能是不同站点（共享主机、CDN、反代）。
  直接拿 IP 直连会探到默认站点甚至完全不同的站点，tech/title 证据失真。
  FOFA 的 host/domain 字段记录了当时的域名，有域名就用域名探测。

约定（与 score.py 共用 pick_probe，两边必须一致）：
  - 探测主机：host / domain 字段里第一个"看起来是域名"的值，否则 ip
  - scheme：优先用 FOFA 的 protocol 字段（实测 443 不一定是 https）
  - 行尾显式 LF（Windows 文本模式默认 CRLF 会毒化 httpx/cdncheck 的输入解析）
  - --scope 提供时先过滤，保证不探授权范围外的资产

退出码：0 成功；2 输入错误；3 授权范围文件不合法。
"""

import argparse
import json
import os
import re
import sys

import scope as scope_mod

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def _looks_like_domain(host):
    return bool(host) and not _IPV4_RE.match(host) and host not in ('localhost',)


def pick_probe(item):
    """挑探活用的 (host, port, scheme)。无法构造时返回 (None, None, None)。
    score.py 用它拼匹配键和输出 url —— 两边共用，禁止各自实现。"""
    if not isinstance(item, dict):
        return None, None, None
    port = str(item.get('port', '')).strip()
    host = ''
    for field in ('host', 'domain'):
        h = scope_mod.norm_host(item.get(field))
        if _looks_like_domain(h):
            host = h
            break
    if not host:
        host = str(item.get('ip') or '').strip()
    if not host:
        # host 字段本身就是裸 IP 的情况
        host = scope_mod.norm_host(item.get('host'))
    if not host or not port:
        return None, None, None
    scheme = str(item.get('protocol') or '').strip().lower()
    if scheme not in ('http', 'https'):
        scheme = 'https' if port == '443' else 'http'
    return host, port, scheme


def build_probe_lines(rows):
    """返回 (targets, urls, hosts)。hosts 按主机去重 —— 同一主机的多个端口
    在 cdncheck 里是同一条记录。"""
    targets, urls, hosts = [], [], []
    for row in rows:
        host, port, scheme = pick_probe(row)
        if not host:
            continue
        targets.append(f'{host}:{port}')
        urls.append(f'{scheme}://{host}:{port}')
        hosts.append(host)
    return (list(dict.fromkeys(targets)), list(dict.fromkeys(urls)),
            list(dict.fromkeys(hosts)))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='从 raw.json 生成 httpx/cdncheck/wafw00f 探活输入（域名优先）')
    ap.add_argument('--raw', required=True, help='FOFA 导出结果')
    ap.add_argument('--prefix', required=True, help='输出前缀，如 data/CVE-2021-44228')
    ap.add_argument('--scope', default=None, help='可选授权范围 JSON；提供时只输出范围内资产')
    args = ap.parse_args(argv)

    try:
        with open(args.raw, encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f'[错误] raw 文件不存在: {args.raw}', file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f'[错误] raw 文件 JSON 损坏: {e}', file=sys.stderr)
        return 2
    rows = data.get('results') if isinstance(data, dict) else data
    if not isinstance(rows, list):
        print('[错误] raw 结构无法识别（既不是数组也不是 {"results":[...]}）', file=sys.stderr)
        return 2

    if args.scope:
        try:
            sc = scope_mod.load_scope(args.scope)
            rows, dropped = scope_mod.filter_rows(rows, sc)
        except scope_mod.ScopeError as e:
            print(f'[错误] {e}', file=sys.stderr)
            return 3
        print(f'scope_filtered={dropped}')

    targets, urls, hosts = build_probe_lines(rows)
    for path, lines in ((f'{args.prefix}_probe_targets.txt', targets),
                        (f'{args.prefix}_probe_urls.txt', urls),
                        (f'{args.prefix}_probe_hosts.txt', hosts)):
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(lines) + ('\n' if lines else ''))
        print(f'{path}={len(lines)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""
Top-N 预筛选（在 WAF/CDN 探测之前）

用途：候选池很大时，先按 score.py 的同一套证据规则排序，只对最值得核验的
top-N 做 cdncheck / wafw00f，把最慢的探测步骤从"全量"降到"top-N"。

输出：
  {prefix}_preselect.json       预排名结果（与 targets.json 同结构，reachability=not_tested）
  {prefix}_probe_top_urls.txt   给 wafw00f 的 scheme://host:port
  {prefix}_probe_top_hosts.txt  给 cdncheck 的裸主机名

用法：
  python tools/prefilter.py --raw data/CVE-XXXX_raw.json \
      --httpx data/CVE-XXXX_httpx.jsonl \
      --context data/CVE-XXXX_context.json \
      --prefix data/CVE-XXXX --probe-limit 100
"""

import argparse
import json
import os
import sys
from urllib.parse import urlsplit

import score


def _host_of(url):
    try:
        return urlsplit(url).hostname or ''
    except ValueError:
        return ''


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='Top-N 预筛选（WAF/CDN 之前）')
    ap.add_argument('--raw', required=True)
    ap.add_argument('--httpx', required=True)
    ap.add_argument('--context', required=True)
    ap.add_argument('--prefix', required=True,
                    help='输出前缀，如 data/CVE-2026-1234')
    ap.add_argument('--probe-limit', type=int, default=100)
    ap.add_argument('--min-score', type=int, default=0,
                    help='预筛选门槛；默认 0 = 取分数最高的 N 条')
    ap.add_argument('--scope', default=None)
    ap.add_argument('--exclude', default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'exclude_keywords.json'))
    args = ap.parse_args(argv)

    raw = score.load_required_json(args.raw, 'raw 导出')
    if isinstance(raw, dict):
        raw = raw.get('results') or raw.get('data')
    if not isinstance(raw, list):
        score._die('raw 结构无法识别')
    context = score.load_required_json(args.context, 'context 情报')
    rules = score.load_json(args.exclude, default={})

    httpx_items, bad, sample = score.load_jsonl(args.httpx)
    if httpx_items is None:
        score._die(f'httpx 输出不存在: {args.httpx}')

    scope = None
    if args.scope:
        import scope as scope_mod
        try:
            scope = scope_mod.load_scope(args.scope)
        except scope_mod.ScopeError as e:
            score._die(str(e), 3)

    kept, stats = score.evaluate_rows(
        raw, httpx_items, [], [], context, rules, scope=scope,
        min_score=args.min_score, limit=args.probe_limit,
        selection='top', cdn_tested=False, waf_tested=False)

    urls, hosts = [], []
    for t in kept:
        url = t.get('url')
        if url:
            urls.append(url)
            h = _host_of(url)
            if h:
                hosts.append(h)
    urls = list(dict.fromkeys(urls))
    hosts = list(dict.fromkeys(hosts))

    preselect = os.path.abspath(args.prefix + '_preselect.json')
    url_path = os.path.abspath(args.prefix + '_probe_top_urls.txt')
    host_path = os.path.abspath(args.prefix + '_probe_top_hosts.txt')
    for p in (preselect, url_path, host_path):
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
    with open(preselect, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(kept, f, ensure_ascii=False, indent=2)
        f.write('\n')
    with open(url_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(urls) + ('\n' if urls else ''))
    with open(host_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(hosts) + ('\n' if hosts else ''))

    print(f"scored={len(kept)}")
    print(f"probe_limit={args.probe_limit}")
    print(f"urls={len(urls)}")
    print(f"hosts={len(hosts)}")
    print(f"preselect={preselect}")
    print(f"urls_out={url_path}")
    print(f"hosts_out={host_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())

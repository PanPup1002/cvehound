"""
资产普查（census 模式）

当 gate 判定版本不可通过 HTTP 观测时，不做探活/评分，只输出 FOFA 层面的
资产普查：总数、导出数、覆盖率、国家分布、标题/org Top N，以及一份
**未探活、未验证** 的候选清单。

用法：
  python tools/census.py --raw data/CVE-XXXX_raw.json \
      --context data/CVE-XXXX_context.json \
      --stats data/CVE-XXXX_stats.json \
      --output data/CVE-XXXX_census.json

产出：
  {output}                 普查汇总 JSON
  {output 同名}.csv        ip,port,host,title,country,org

退出码：0 成功；2 输入错误。
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter


def load_json(path, default=None):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as e:
        print(f'[warn] {path} JSON 损坏: {e}', file=sys.stderr)
        return default


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='资产普查（census 模式）')
    ap.add_argument('--raw', required=True)
    ap.add_argument('--context', required=True)
    ap.add_argument('--stats', default=None, help='fofa_stats 输出 JSON')
    ap.add_argument('--output', required=True, help='如 data/CVE-x_census.json')
    ap.add_argument('--top', type=int, default=20)
    args = ap.parse_args(argv)

    raw = load_json(args.raw, None)
    if raw is None:
        print(f'[错误] raw 不存在或损坏: {args.raw}', file=sys.stderr)
        return 2
    if isinstance(raw, dict):
        raw = raw.get('results') or raw.get('data')
    if not isinstance(raw, list):
        print('[错误] raw 结构无法识别', file=sys.stderr)
        return 2
    context = load_json(args.context, {}) or {}
    stats = load_json(args.stats, {}) if args.stats else {}

    total = None
    if isinstance(stats, dict):
        total = stats.get('size')
    if total is None:
        total = context.get('fofa_total')
    exported = len(raw)
    coverage = round(exported / total, 6) if isinstance(total, int) and total > 0 else None

    countries = Counter(
        (str(r.get('country') or 'unknown').strip() or 'unknown')
        for r in raw if isinstance(r, dict))
    titles = Counter(
        str(r.get('title') or '').strip()
        for r in raw if isinstance(r, dict) and str(r.get('title') or '').strip())
    orgs = Counter(
        str(r.get('org') or '').strip()
        for r in raw if isinstance(r, dict) and str(r.get('org') or '').strip())

    summary = {
        'schema_version': 1,
        'cve_id': context.get('cve_id'),
        'product': context.get('product'),
        'query': context.get('fofa_query') or context.get('matched_fingerprint'),
        'mode': 'census',
        'note': '0 条可验证候选；这是资产普查，不是漏洞清单。未探活、未验证。',
        'fofa_total': total,
        'exported': exported,
        'coverage_ratio': coverage,
        'country': dict(countries.most_common(args.top)),
        'country_unknown': countries.get('unknown', 0),
        'title_top': dict(titles.most_common(args.top)),
        'org_top': dict(orgs.most_common(args.top)),
    }

    out = os.path.abspath(args.output)
    d = os.path.dirname(out)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write('\n')

    csv_path = os.path.splitext(out)[0] + '.csv'
    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'port', 'host', 'title', 'country', 'org'])
        for r in raw:
            if not isinstance(r, dict):
                continue
            w.writerow([r.get('ip', ''), r.get('port', ''), r.get('host', ''),
                        r.get('title', ''), r.get('country', ''), r.get('org', '')])

    print(f'total={total}')
    print(f'exported={exported}')
    print(f'coverage_ratio={coverage}')
    print(f'countries={len(countries)} unknown={countries.get("unknown", 0)}')
    print(f'output={out}')
    print(f'csv={csv_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

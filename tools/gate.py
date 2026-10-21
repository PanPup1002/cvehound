"""
可验证性闸门（Step 0.5）

判定一个 CVE 是否值得进入完整探活流程：
  - 版本可通过 HTTP 观测（产品有专用版本端点 / 响应头白名单 / context 显式指定）
      -> candidates：继续完整流程
  - 否则
      -> census：只做 FOFA 统计与导出（资产普查），不跑 httpx/cdncheck/wafw00f/评分

用法：
  python tools/gate.py --context data/CVE-XXXX_context.json \
      --output data/CVE-XXXX_gate.json
  python tools/gate.py --context ... --stats data/CVE-XXXX_stats.json \
      --cohort-size 31702 --output ...

退出码：0 成功；2 输入错误。
"""

import argparse
import json
import os
import sys

import version_compare
from version_probe import load_json, matching_rules

# 版本通常出现在响应头/tech 的产品（与 score.py 的白名单保持一致）
HEADER_VERSION_PRODUCTS = {
    'apache http server', 'nginx', 'iis', 'microsoft-iis', 'tengine',
    'lighttpd', 'caddy', 'openresty', 'tomcat', 'jetty', 'undertow',
    'wildfly', 'jboss',
}


def _norm(value):
    import re
    return re.sub(r'[^a-z0-9]+', ' ', str(value or '').lower()).strip()


def _header_version_product(product):
    p = _norm(product)
    if not p:
        return False
    if p in HEADER_VERSION_PRODUCTS:
        return True
    return any(w in p.split() for w in HEADER_VERSION_PRODUCTS if len(w) >= 4)


def assess(context, stats=None, cohort_size=None, table=None,
           max_probe=2000, waf_top=100):
    """返回 gate 决策 dict。"""
    table = table or {}
    product = str(context.get('product') or '').strip()
    reasons, warnings = [], []

    run_mode = str(context.get('run_mode') or 'auto').lower()
    if run_mode not in ('auto', 'candidates', 'census'):
        run_mode = 'auto'

    if not product:
        return {
            'schema_version': 1,
            'cve_id': context.get('cve_id'),
            'product': '',
            'decision': 'blocked',
            'ceiling': 'C',
            'version_observable': False,
            'reasons': ['product 为空，无法构造有效指纹'],
            'warnings': [],
            'probe_plan': {},
            'cohort_size': cohort_size,
        }

    specific_rules = [r for r in (table.get('rules') or [])
                      if '*' not in (r.get('products') or [])]
    has_specific_rule = bool(matching_rules(product, {'rules': specific_rules}))
    has_explicit_paths = bool(
        (context.get('version_probe') or {}).get('paths'))
    header_observable = _header_version_product(product)

    explicit = context.get('version_observable')
    if explicit is True:
        version_observable = True
        reasons.append('context.version_observable=true')
    elif explicit is False:
        version_observable = False
        reasons.append('context.version_observable=false')
    else:
        version_observable = bool(
            has_specific_rule or has_explicit_paths or header_observable)
        if has_specific_rule:
            reasons.append('产品有专用版本探测规则')
        if has_explicit_paths:
            reasons.append('context 指定了版本探测路径')
        if header_observable:
            reasons.append('产品版本通常出现在响应头/tech')

    if run_mode == 'census':
        version_observable = False
        reasons = ['context.run_mode=census 强制普查']
    elif run_mode == 'candidates':
        # 只强制走完整流程，不伪造 version_observable。
        # 版本不可观测时 ceiling 仍应为 B（affected 不可达）。
        reasons.append('context.run_mode=candidates 强制执行完整流程')

    affected = version_compare.select_ranges(context)
    if not affected:
        warnings.append('NVD 无可用版本区间；即使探测到版本也无法判定 affected')

    total = cohort_size
    if total is None and isinstance(stats, dict):
        total = stats.get('size')
    sampled = isinstance(total, int) and total > max_probe

    if run_mode == 'census':
        decision = 'census'
        ceiling = 'C'
        reasons.append('context.run_mode=census 显式要求普查；跳过探活与评分')
        probe_plan = {
            'httpx': {'enabled': False, 'max_targets': 0},
            'cdn': {'enabled': False, 'max_targets': 0},
            'waf': {'enabled': False, 'top': 0},
            'version_probe': {'enabled': False, 'max_targets': 0},
        }
    else:
        # 默认执行探活与评分。版本不可观测只影响天花板（affected 不可达），
        # 不再因此跳过 httpx/评分——否则会丢失 tier B 的资产候选。
        decision = 'sampled' if sampled else 'candidates'
        if sampled:
            reasons.append(f'候选池 {total} 超过探活上限 {max_probe}，需要分层抽样')
        if not version_observable:
            ceiling = 'B'
            reasons.append('版本不可通过 HTTP 观测：仍执行探活与评分，'
                           '但 affected 不可达，最高 tier B')
        elif not affected:
            ceiling = 'B'
        else:
            ceiling = 'A'
        probe_plan = {
            'httpx': {'enabled': True, 'max_targets': max_probe},
            'cdn': {'enabled': False, 'max_targets': 0,
                    'note': '默认关闭；仅 top-N 按需开启'},
            'waf': {'enabled': False, 'top': waf_top,
                    'note': '默认关闭；仅 top-N 按需开启'},
            'version_probe': {'enabled': True, 'max_targets': min(50, max_probe)},
        }

    return {
        'schema_version': 1,
        'cve_id': context.get('cve_id'),
        'product': product,
        'decision': decision,
        'ceiling': ceiling,
        'version_observable': version_observable,
        'affected_ranges': len(affected),
        'cohort_size': total,
        'reasons': reasons,
        'warnings': warnings,
        'probe_plan': probe_plan,
    }


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description='可验证性闸门（Step 0.5）')
    ap.add_argument('--context', required=True)
    ap.add_argument('--stats', default=None, help='fofa_stats 输出 JSON')
    ap.add_argument('--cohort-size', type=int, default=None)
    ap.add_argument('--table', default=os.path.join(here, 'version_probes.json'))
    ap.add_argument('--max-probe', type=int, default=2000)
    ap.add_argument('--waf-top', type=int, default=100)
    ap.add_argument('--output', required=True)
    args = ap.parse_args(argv)

    context = load_json(args.context, None)
    if not isinstance(context, dict):
        print(f'[错误] context 不存在或损坏: {args.context}', file=sys.stderr)
        return 2
    stats = load_json(args.stats, {}) if args.stats else {}
    table = load_json(args.table, {}) or {}

    gate = assess(context, stats=stats, cohort_size=args.cohort_size,
                  table=table, max_probe=args.max_probe,
                  waf_top=args.waf_top)

    d = os.path.dirname(os.path.abspath(args.output))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(gate, f, ensure_ascii=False, indent=2)
        f.write('\n')

    print(f"decision={gate['decision']}")
    print(f"ceiling={gate['ceiling']}")
    print(f"version_observable={gate['version_observable']}")
    print(f"cohort_size={gate.get('cohort_size')}")
    for r in gate.get('reasons') or []:
        print(f'reason={r}')
    for w in gate.get('warnings') or []:
        print(f'warning={w}')
    print(f'output={os.path.abspath(args.output)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

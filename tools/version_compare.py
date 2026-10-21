"""
版本比较 + NVD 影响区间提取。

不再用「正则抓版本号取 min/max」的办法——那会把多区间、带空档、
带排除版本的 CVE 判错。以 CVE-2021-44228 为例，影响范围是三段不连续区间：
    2.0.1  <= v <  2.3.1
    2.4.0  <= v <  2.12.2
    2.13.0 <= v <  2.15.0
min/max 写法会算成 2.0.1 ~ 2.15.0 一整段，把空档里的 2.12.5 判成受影响。

对外接口
    compare(version, affected_ranges, excluded_versions=None)
        -> "affected" | "unaffected" | "unknown"
    select_ranges(context)
        -> 从 context 里挑出适用于 context["product"] 的区间列表
    extract_ranges_from_nvd(nvd_payload, product)
        -> {"affected_ranges": [...], "affected_ranges_by_product": {...},
            "warnings": [...]}

    CLI（给 cve-recon 在 Step 1 里调用，避免靠肉眼数 cpeMatch 条目）：
        python tools/version_compare.py --nvd data/XXX_nvd.json \
            --product "ThinkPHP" --output data/XXX_ranges.json

affected_ranges 结构：
    [{"start": "2.4.0", "start_inclusive": true,
      "end": "2.4.50", "end_inclusive": false}]
    start / end 为 null 表示该侧无边界。

边界默认值（与 NVD 习惯一致）：只写 start 时按闭区间，
只写 end 时按开区间；显式给了 *_inclusive 就以给的为准。

TODO: 无。精确版本条目已按规则 c 建成退化闭区间（start == end）。
      将来若要区分 "2.0-beta9" 与 "2.0" 这类同数字前缀的预发布版本，
      需要给 parse_version 加预发布后缀感知——当前按前导数字比对，两者同值。
"""

import re

_LEADING_NUM_RE = re.compile(r'^\s*[A-Za-z]?(\d+(?:\.\d+)*)')
_NORM_RE = re.compile(r'[^a-z0-9]+')

# (cpeMatch 字段名, 归到哪一侧, 该侧是否为闭区间)
_BOUND_KEYS = (
    ('versionStartIncluding', 'start', True),
    ('versionStartExcluding', 'start', False),
    ('versionEndIncluding', 'end', True),
    ('versionEndExcluding', 'end', False),
)


# --------------------------------------------------------------------------
# 版本比较
# --------------------------------------------------------------------------

def parse_version(value):
    """抽出前导数字版本并转成元组，便于逐段数值比较。
        '2.4.39' -> (2,4,39)   '2.0-beta9' -> (2,0)   'v1.2' -> (1,2)
        'R81.20' -> (81,20)    （Check Point 等厂商用单字母前缀）
    解析不出来返回 None —— 调用方据此给 unknown，不做任何猜测。"""
    if value is None:
        return None
    m = _LEADING_NUM_RE.match(str(value).strip())
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split('.'))
    except ValueError:
        return None


def compare_versions(a, b):
    """比较两个已解析的版本元组。a<b 返回 -1，相等 0，a>b 返回 1。
    长度不等时右侧补 0，使 (2,4) 与 (2,4,0) 视为相等。"""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _contains(ver, rng):
    start = parse_version(rng.get('start'))
    end = parse_version(rng.get('end'))
    if start is not None:
        c = compare_versions(ver, start)
        if c < 0 or (c == 0 and not rng.get('start_inclusive', True)):
            return False
    if end is not None:
        c = compare_versions(ver, end)
        if c > 0 or (c == 0 and not rng.get('end_inclusive', False)):
            return False
    return True


def compare(version, affected_ranges, excluded_versions=None):
    """返回 'affected' / 'unaffected' / 'unknown'。

    三态语义：
      affected    版本可解析，且落在某个影响区间内（且不在排除列表里）
      unaffected  版本可解析，且明确落在所有区间之外 —— 调用方应硬剔除
      unknown     版本拿不到 / 解析不了 / 没有任何可用区间 —— 保留，低优先，
                  绝不因为「判断不了」就把目标删掉，也绝不当成 affected
    """
    ver = parse_version(version)
    if ver is None:
        return 'unknown'

    ranges = [r for r in (affected_ranges or []) if isinstance(r, dict)]
    # 至少要有一侧边界能解析，否则这个「区间」等于「全部版本」，
    # 不可作为 affected 的依据
    usable = [r for r in ranges
              if parse_version(r.get('start')) is not None
              or parse_version(r.get('end')) is not None]
    if not usable:
        return 'unknown'

    for ex in (excluded_versions or []):
        ev = parse_version(ex)
        if ev is not None and compare_versions(ver, ev) == 0:
            return 'unaffected'

    for rng in usable:
        if _contains(ver, rng):
            return 'affected'
    return 'unaffected'


# --------------------------------------------------------------------------
# 从 context 里挑区间
# --------------------------------------------------------------------------

def _norm_name(value):
    return _NORM_RE.sub(' ', str(value or '').lower()).strip()


def _name_match(a, b):
    """产品名匹配：整体包含，或最后一个词互相包含
    （让 "apache:log4j" 能匹配上产品名 "Apache Log4j2"）。

    末词比对有两道约束，都是实测踩出来的：
      - 长度 >= 4：否则 "siemens spectrum power 4" 的末词 "4"
        会命中 "apache log4j2"（里面正好有个字符 4），把西门子的区间
        并进 log4j 的扁平列表
      - 不能是纯数字：同理
    """
    if not a or not b:
        return False
    if a == b or a in b or b in a:
        return True
    ta = a.split()[-1] if a.split() else ''
    tb = b.split()[-1] if b.split() else ''
    for x, y in ((ta, tb), (tb, ta)):
        if len(x) >= 4 and not x.isdigit() and x in y:
            return True
    return False


def select_ranges(context):
    """挑出适用于 context["product"] 的影响区间。
    优先按 affected_ranges_by_product 分组匹配；匹配不上或没有分组时退回扁平
    affected_ranges。都拿不到返回 []（→ 判定 unknown，不猜）。"""
    by_product = context.get('affected_ranges_by_product') or {}
    flat = context.get('affected_ranges') or []
    prod = _norm_name(context.get('product', ''))
    if isinstance(by_product, dict) and by_product and prod:
        for key, ranges in by_product.items():
            if isinstance(ranges, list) and _name_match(prod, _norm_name(key)):
                return ranges
    return flat


# --------------------------------------------------------------------------
# 从 NVD cpeMatch 提取影响区间
# --------------------------------------------------------------------------

def _clean_bound(value):
    """版本边界值清洗：空 / "*" / "-" 都视为无边界。"""
    s = str(value).strip() if value is not None else ''
    return None if (not s or s in ('*', '-')) else s


def _exact_version_from_criteria(criteria):
    """从 CPE 名里取精确版本。
        cpe:2.3:a:vendor:product:VERSION:UPDATE:edition:...
                          ^parts[5]  ^parts[6]
    版本字段是 "*" / "-" 时返回 None —— 那是"任意版本"，不是精确版本信息。
    update 字段有值（如 2.0:beta9）时拼成 "2.0-beta9"，供展示和比对。"""
    parts = str(criteria or '').split(':')
    if len(parts) < 6:
        return None
    ver = _clean_bound(parts[5])
    if ver is None:
        return None
    upd = _clean_bound(parts[6]) if len(parts) > 6 else None
    return f'{ver}-{upd}' if upd else ver


def _product_key(criteria):
    """cpe:2.3:a:apache:log4j:... -> "apache:log4j"。"""
    parts = str(criteria or '').split(':')
    if len(parts) >= 5 and parts[3] and parts[4]:
        return f'{parts[3]}:{parts[4]}'
    return 'unknown'


def extract_ranges_from_nvd(payload, product=''):
    """从 nvd_get_cve 的返回里提取结构化影响区间。

    提取规则：
      a) 只取 vulnerable=true 的 cpeMatch（vulnerable=false 是"不受影响版本"）
      b) 优先保留 criteria 与 product 匹配的产品分组；一个都匹配不上时
         保留全部分组并在 warnings 里说明
      c) 生成区间的三种情况：
         - 有 versionEnd* → 用起止边界（start 缺失记 None，由 compare 按无下界处理）
         - 只有 versionStart* 没有 versionEnd* → 不生成（没有上界的区间等于全量）
         - 边界字段全缺 → 退回 CPE 里的精确版本，生成退化闭区间
           {start: v, start_inclusive: true, end: v, end_inclusive: true}
           **不要丢弃** —— "只有精确版本"是 NVD 的常见形态，尤其框架类 CVE。
           丢了它等于框架类 CVE 永远拿不到 affected。
         "*" / "-" 一律视为无边界
      d) 多个产品时额外输出 affected_ranges_by_product 分组
    """
    cves = payload.get('cves') if isinstance(payload, dict) else None
    if isinstance(cves, list) and cves:
        cve = cves[0] if isinstance(cves[0], dict) else {}
    elif isinstance(payload, dict):
        cve = payload
    else:
        cve = {}

    warnings = []
    by_product = {}
    for node in (cve.get('configurationNodes') or []):
        if not isinstance(node, dict):
            continue
        for m in (node.get('cpeMatch') or []):
            if not isinstance(m, dict) or not m.get('vulnerable'):
                continue                                    # (a)
            start = end = None
            start_incl, end_incl = True, False
            for field, side, incl in _BOUND_KEYS:
                val = _clean_bound(m.get(field))
                if val is None:
                    continue
                if side == 'start':
                    start, start_incl = val, incl
                else:
                    end, end_incl = val, incl

            if start is None and end is None:
                exact = _exact_version_from_criteria(m.get('criteria'))
                if exact is None:
                    continue                                # 版本字段也是通配，真没信息
                start = end = exact                         # (c) 退化闭区间
                start_incl = end_incl = True
            elif end is None:
                continue                                    # (c) 只有下界，不生成

            by_product.setdefault(_product_key(m.get('criteria')), []).append({
                'start': start,
                'start_inclusive': start_incl,
                'end': end,
                'end_inclusive': end_incl,
            })

    if not by_product:
        warnings.append('cpeMatch 里没有可用的版本区间（连精确版本条目都没有）')
        return {'affected_ranges': [], 'warnings': warnings}

    # 去重
    for key in list(by_product):
        seen, uniq = set(), []
        for r in by_product[key]:
            t = (r['start'], r['start_inclusive'], r['end'], r['end_inclusive'])
            if t in seen:
                continue
            seen.add(t)
            uniq.append(r)
        by_product[key] = uniq

    prod_n = _norm_name(product)
    matched = [k for k in by_product if _name_match(prod_n, _norm_name(k))]  # (b)
    if prod_n and not matched:
        warnings.append(
            f'没有 cpeMatch 与产品 "{product}" 匹配，已保留全部 '
            f'{len(by_product)} 个产品的区间（可能过度匹配）')
    selected = matched or list(by_product)

    flat = []
    for key in selected:
        for r in by_product[key]:
            if r not in flat:
                flat.append(r)

    out = {'affected_ranges': flat, 'warnings': warnings}
    if len(by_product) > 1:                                 # (d)
        out['affected_ranges_by_product'] = {k: by_product[k] for k in selected}
    return out


def _main(argv=None):
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(
        description='从 nvd_get_cve 的原始 JSON 提取 affected_ranges')
    ap.add_argument('--nvd', required=True, help='nvd_get_cve 返回落盘的文件')
    ap.add_argument('--product', default='', help='目标产品名，用于挑产品分组')
    ap.add_argument('--output', help='输出 JSON 路径；省略则打印到 stdout')
    args = ap.parse_args(argv)

    with open(args.nvd, encoding='utf-8') as f:
        payload = _json.load(f)
    result = extract_ranges_from_nvd(payload, args.product)
    text = _json.dumps(result, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text + '\n')
        print(f"affected_ranges={len(result['affected_ranges'])}")
        print(f"products={len(result.get('affected_ranges_by_product', {}))}")
        print(f"warnings={len(result['warnings'])}")
        for w in result['warnings']:
            print(f"  [warn] {w}")
        print(f"output={args.output}")
    else:
        print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())

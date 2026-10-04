"""
CVE 目标质量评分脚本

定位：给人工核验用的目标清单打分排序，不做任何漏洞利用动作。

输入
  --raw       FOFA 导出结果（顶层 JSON 数组，或 {"results": [...]}）
  --httpx     httpx 探活输出（JSONL；匹配键 = input 字段，原样回显探活输入行 ip:port。
              不要用 url 字段做匹配——httpx 探测失败时会降级到别的端口，url 不可信）
  --cdn       cdncheck 输出（JSONL；只有命中 CDN/WAF 的目标才有输出行。
              匹配键 input 是裸主机名——cdncheck v1.3.1 拒绝 host:port 输入，
              要用 probe_inputs.py 产出的 _probe_hosts.txt 喂它）
  --waf       wafw00f 输出（JSON 数组；每个输入对应一条，匹配键 = url 去掉 scheme）
  --context   CVE 情报（JSON：product / affected_ranges / excluded_versions /
              matched_fingerprint / verify_path）
  --output    目标清单输出路径（.json）；同目录同名 .txt / .csv 一并写出
  --scope     可选授权范围 JSON（tools/scope.py 格式）；提供时强制剔除范围外资产

输出
  {output}.json  全字段目标列表（match_score 降序，门槛默认 40 分、上限 100 条）
  {output}.txt   每行一个 URL（显式 LF 行尾，Windows 下文本模式默认 CRLF 会毒化下游工具）
  {output}.csv   ip,port,url,title,server,version,match_score,reachability
                 （utf-8-sig，Excel 直接打开不乱码）

评分模型
  match_score（0-100，决定分类与排序）：
    +30  httpx tech[] 命中 context.product（词首匹配，防 PHP↔ThinkPHP 假命中）
    +30  FOFA title 命中 context.product（子串匹配，matched_fingerprint 回退）——
         指纹库盲区（wappalyzer 无该产品指纹的框架类 CVE）的 FOFA 证据通道
    +20  标题证据非空（httpx title 优先；httpx 无标题但 FOFA 标题命中产品时
         由 FOFA 标题回退充当，二者不叠加）
    +30  有可靠版本号（至少一条 versions 证据）
    +20  version_status == "affected"
  CDN/WAF 不参与 match_score，只影响可达性成本：

分类（四档，取代单一阈值）：
    likely_affected    ≥80 且 version_status == "affected"
    probable           ≥60（≥80 但版本状态非 affected 时降档到此）
    needs_verification ≥40（默认输出门槛，--min-score 可调）
    rejected           <40，不输出

  reachability      direct / waf / cdn / cdn+waf
  verification_cost direct=10, waf=30, cdn=40, cdn+waf=60

版本判断三态（由 tools/version_compare.py 基于 NVD 结构化边界计算）：
  affected    版本可解析且在影响区间内
  unaffected  版本可解析且明确在区间外 —— 硬剔除
  unknown     版本拿不到/无法比较 —— 保留，低优先

硬排除：对 org 做「英文词边界正则 / 中文子串」两类匹配，
词表在 tools/exclude_keywords.json，命中即整条剔除。

退出码：0 成功；2 必需输入（raw/httpx/context）缺失或损坏；3 授权范围文件不合法。
cdn / waf 为可选输入：缺失仅告警不阻塞（cdncheck 在部分网络环境不可用）。
"""

import argparse
import csv
import json
import os
import re
import sys

import probe_inputs
import scope as scope_mod
import version_compare

VER_RE = re.compile(r'\d+(?:\.\d+){1,2}')

# versions 证据各来源的可信度
SOURCE_RELIABILITY = {
    'httpx_tech': 0.90,
    'webserver_header': 0.85,
    'fofa_server': 0.80,
    'x_powered_by': 0.80,
    'response_body': 0.60,
    'cookie': 0.50,
}

VERIFICATION_COST = {'direct': 10, 'waf': 30, 'cdn': 40, 'cdn+waf': 60}

# Server 头对哪些产品具有「版本权威性」。
# 只有这些产品的 Server 头版本才被采信 —— 因为 Server 头是自由文本
# （"Apache/2.4.39 (Win64)..."），用「产品名首词」去锚定会把 Web 服务器版本
# 错记到库头上：product="Apache Log4j2" 会拿到 2.4.39，而 2.4.39 落在
# Log4Shell 影响区间内，于是一台普通 Apache 服务器被误判成 affected（实测复现）。
SERVER_HEADER_PRODUCTS = (
    'apache http server', 'nginx', 'iis', 'microsoft-iis',
    'tengine', 'lighttpd', 'caddy', 'openresty',
    'tomcat', 'jetty', 'undertow', 'wildfly', 'jboss',
)


def _norm_prod(value):
    return re.sub(r'[^a-z0-9]+', ' ', str(value or '').lower()).strip()


_SERVER_HEADER_PRODUCTS_NORM = {_norm_prod(p) for p in SERVER_HEADER_PRODUCTS}


def _server_header_trusted(product):
    """产品是否属于「Server 头版本可信」的白名单。
    先整体匹配，再退回按完整单词匹配（让 "Apache Tomcat" 命中白名单里的 "tomcat"，
    同时让 "Apache Log4j2" 命中不了任何条目）。"""
    p = _norm_prod(product)
    if not p:
        return False
    if p in _SERVER_HEADER_PRODUCTS_NORM:
        return True
    return any(re.search(r'\b' + re.escape(w) + r'\b', p)
               for w in _SERVER_HEADER_PRODUCTS_NORM if len(w) >= 4)


def load_json(path, default=None):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {} if default is None else default
    except json.JSONDecodeError as e:
        print(f"[warn] {path} 不是合法 JSON，按空处理: {e}", file=sys.stderr)
        return {} if default is None else default


def load_jsonl(path):
    """返回 (items, bad_count, bad_sample)。
    文件不存在时 items 为 None —— 调用方据此区分「缺失」与「内容损坏」。"""
    items, bad, sample = [], 0, ''
    try:
        with open(path, encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    bad += 1
                    if not sample:
                        sample = f'第{lineno}行: {line[:80]}'
    except FileNotFoundError:
        return None, 0, ''
    return items, bad, sample


def _die(msg, code=2):
    print(f'[错误] {msg}', file=sys.stderr)
    sys.exit(code)


def load_required_json(path, label):
    """必需输入：缺失或损坏立即终止（退出码 2），不允许静默出空结果。"""
    if not os.path.exists(path):
        _die(f'{label} 不存在: {path}')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        _die(f'{label} JSON 损坏: {e}')


def norm_key(value):
    """统一匹配键为 host:port 形态。
    httpx input / cdncheck input 原样回显探活行；wafw00f url 带 scheme，需要剥掉。"""
    s = str(value or '').strip()
    if '://' in s:
        s = s.split('://', 1)[1]
    return s.rstrip('/').lower()


def org_exclusion_hit(org, rules):
    """对 org 做硬排除匹配。英文关键词用词边界正则（避免 mil 误伤 Milan/Emilia），
    中文关键词没有词边界问题，用子串判断。返回 (类别, 关键词) 或 None。"""
    if not org:
        return None
    org_l = org.lower()
    for category, keywords in (rules or {}).items():
        if not isinstance(keywords, list):
            continue
        for kw in keywords:
            kw = str(kw)
            if not kw:
                continue
            if kw.isascii():
                if re.search(r'\b' + re.escape(kw.lower()) + r'\b', org_l):
                    return category, kw
            else:
                if kw in org:
                    return category, kw
    return None


def tech_hit(product, tech):
    """httpx tech[] 是否命中 context.product。
    用与版本归属相同的词首匹配（_tech_name_matches）——裸双向子串会让
    "PHP" 假命中 "ThinkPHP"，词首匹配不会（回归用例已钉住该场景）。"""
    for t in tech:
        stem = str(t).split(':')[0].strip()
        if stem and _tech_name_matches(product, stem):
            return True
    return False


def fofa_title_hit(product, fingerprint, title):
    """FOFA 标题是否命中产品（或匹配指纹）。指纹库盲区通道：wappalyzer 没有
    该产品指纹时（框架类 CVE），FOFA 抓到的页面标题若显式点名产品
    （如「系统登录 · ThinkAdmin」），就是可靠的产品证据。
    子串匹配（小写化）；先试 product，再回退 matched_fingerprint——
    多词产品的标题通常只写短名（"Apache Log4j2" 的页面只写 "Log4j2"）。"""
    t = str(title or '').lower()
    if not t:
        return False
    for needle in (product, fingerprint):
        n = str(needle or '').strip().lower()
        if n and n in t:
            return True
    return False


def _tech_name_matches(product, name):
    """tech 条目名与产品名是否指同一产品。按词首匹配，双向。
        "log4j" 命中 "log4j2"（Apache Log4j2 的产品名里带 2）
        但 "php" 命中不了 "thinkphp"（避免把 ThinkPHP 的版本记到 PHP 头上）
    """
    prod = _norm_prod(product).split()
    nm = _norm_prod(name).split()
    if not prod or not nm:
        return False
    if prod == nm:
        return True
    return any(a.startswith(b) or b.startswith(a) for a in prod for b in nm)


def collect_versions(product, webserver, fofa_server, tech, header):
    """收集「产品 -> 版本」证据，每条带来源和可信度，按可信度降序返回。

    response_body / cookie 两个来源当前拿不到数据（FOFA 的 body 字段被账户等级
    禁用 [820001]，httpx 也没抓 body），分支先留空，等数据源接上再启用。
    """
    out = []

    # httpx tech[]：wappalyzer 结果，可信度最高。形如 "Nginx:1.16.1"
    for t in tech:
        t = str(t)
        if ':' not in t:
            continue
        name, _, ver = t.partition(':')
        name, ver = name.strip(), ver.strip()
        if not ver or not _tech_name_matches(product, name):
            continue
        if version_compare.parse_version(ver) is None:
            continue
        out.append({'product': name, 'version': ver, 'source': 'httpx_tech',
                    'reliability': SOURCE_RELIABILITY['httpx_tech']})

    # httpx webserver / FOFA server：只有当产品本身属于
    # SERVER_HEADER_PRODUCTS 白名单时才采信，且不依赖产品名匹配。
    # 白名单外一律不采信；tech[] 的提取不受影响（见上面的分支）。
    if _server_header_trusted(product):
        for text, source in ((webserver, 'webserver_header'), (fofa_server, 'fofa_server')):
            if not text:
                continue
            m = VER_RE.search(str(text))
            if m:
                out.append({'product': product, 'version': m.group(0),
                            'source': source,
                            'reliability': SOURCE_RELIABILITY[source]})

    # FOFA header 里的 X-Powered-By
    for line in str(header or '').splitlines():
        if line.lower().startswith('x-powered-by:'):
            val = line.split(':', 1)[1].strip() if ':' in line else ''
            if val and _tech_name_matches(product, val):
                m = VER_RE.search(val)
                if m:
                    out.append({'product': product, 'version': m.group(0),
                                'source': 'x_powered_by',
                                'reliability': SOURCE_RELIABILITY['x_powered_by']})

    seen = set()
    uniq = []
    for v in sorted(out, key=lambda x: -x['reliability']):
        k = (v['source'], v['version'])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(v)
    return uniq


def build_hint(is_waf, version_status, verify_path):
    """verify_hint 按优先级生成。verify_path 为空是常态，退回通用说法，不报错。
    措辞保持中性（「授权范围内人工核验」）——不出现「绕过 WAF」这类
    不适合作为默认自动化建议的表述。"""
    suffix = f'；建议验证路径: {verify_path}' if verify_path else ''
    if version_status == 'affected':
        if is_waf:
            return '版本命中影响范围；存在WAF，人工核验时留意WAF拦截' + suffix
        return '版本命中影响范围，建议在授权范围内人工核验' + suffix
    if is_waf:
        return '需手动确认指纹后再核验（存在WAF）'
    return '需手动确认指纹后再核验'


def classify(match_score, version_status):
    """四档分类（改进方案 §9.2）。
    likely_affected 加 version_status == "affected" 护栏：有版本证据但适用性
    未知（如 context 无可用区间）时最高只到 probable，避免把 unknown 当 affected。"""
    if match_score >= 80 and version_status == 'affected':
        return 'likely_affected'
    if match_score >= 60:
        return 'probable'
    if match_score >= 40:
        return 'needs_verification'
    return 'rejected'


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='CVE 目标质量评分')
    ap.add_argument('--raw', required=True)
    ap.add_argument('--httpx', required=True)
    ap.add_argument('--cdn', required=True)
    ap.add_argument('--waf', required=True)
    ap.add_argument('--context', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--scope', default=None,
                    help='可选授权范围 JSON；提供时强制剔除范围外资产')
    ap.add_argument('--min-score', type=int, default=40)
    ap.add_argument('--limit', type=int, default=100)
    ap.add_argument('--exclude',
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         'exclude_keywords.json'))
    args = ap.parse_args()

    raw = load_required_json(args.raw, 'raw 导出')
    if isinstance(raw, dict):
        raw = raw.get('results') or raw.get('data')
    if not isinstance(raw, list):
        _die('raw 结构无法识别（既不是数组也不是 {"results":[...]}）')
    context = load_required_json(args.context, 'context 情报')
    rules = load_json(args.exclude, default={})

    # httpx 是必需输入；cdn / waf 是可选输入（cdncheck 部分网络不可用，缺失不阻塞）
    httpx_items, httpx_bad, httpx_sample = load_jsonl(args.httpx)
    if httpx_items is None:
        _die(f'httpx 输出不存在: {args.httpx}')
    if httpx_bad:
        print(f'[warn] httpx 输出有 {httpx_bad} 行损坏（{httpx_sample}）',
              file=sys.stderr)
    if not httpx_items and httpx_bad:
        _die('httpx 输出全部损坏，无法评分')
    cdn_items, cdn_bad, cdn_sample = load_jsonl(args.cdn)
    if cdn_items is None:
        print('[warn] cdn 输入缺失，reachability 按无 CDN 处理', file=sys.stderr)
        cdn_items = []
    if cdn_bad:
        print(f'[warn] cdn 输出有 {cdn_bad} 行损坏（{cdn_sample}）', file=sys.stderr)

    waf_rows = load_json(args.waf, default=[])
    if isinstance(waf_rows, dict):
        waf_rows = waf_rows.get('results') or waf_rows.get('data') or []

    # 可选授权范围：提供即强制（探活侧已过滤一次，这里再兜底一次）
    scope = None
    if args.scope:
        try:
            scope = scope_mod.load_scope(args.scope)
        except scope_mod.ScopeError as e:
            _die(str(e), 3)
    if scope:
        raw, out_of_scope = scope_mod.filter_rows(raw, scope)
    else:
        out_of_scope = 0

    product = str(context.get('product', '')).strip()
    affected_ranges = version_compare.select_ranges(context)
    excluded_versions = context.get('excluded_versions') or []
    fingerprint = str(context.get('matched_fingerprint', '')).strip()
    verify_path = str(context.get('verify_path', '')).strip()

    # httpx 索引：键 = input（原样回显探活输入行 host:port）
    httpx_by_key = {}
    for row in httpx_items:
        key = norm_key(row.get('input') or row.get('url'))
        if key and key not in httpx_by_key:
            httpx_by_key[key] = row

    # cdncheck 索引：非命中目标没有输出行，缺席 = 不是 CDN/WAF
    cdn_by_key = {}
    for row in cdn_items:
        key = norm_key(row.get('input'))
        if key:
            cdn_by_key[key] = row

    # wafw00f 索引：每个输入都有输出，url 带 scheme
    waf_by_key = {}
    for row in waf_rows:
        key = norm_key(row.get('url'))
        if key:
            waf_by_key[key] = row

    stats = {'raw': len(raw), 'out_of_scope': out_of_scope, 'skipped': 0,
             'org_excluded': 0, 'no_httpx': 0, 'bad_status': 0,
             'version_unaffected': 0, 'scored': 0, 'fofa_title_hit': 0,
             'below_score': 0, 'final': 0, 'truncated': False}

    targets = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ip = str(item.get('ip') or '').strip() \
            or str(item.get('host') or '').split(':')[0].strip()
        probe_host, port, scheme = probe_inputs.pick_probe(item)
        if not ip or not port or not probe_host:
            stats['skipped'] += 1
            continue
        # 匹配键：探活输入是「域名优先」生成的（tools/probe_inputs.py），
        # 用同一函数还原键；再回退 ip:port 以兼容按 IP 探测的旧数据
        probe_key = norm_key(f'{probe_host}:{port}')
        ip_key = norm_key(f'{ip}:{port}')

        # ---- 硬排除（本地做，FOFA 侧的 org 过滤实测是 no-op）----
        hit = org_exclusion_hit(str(item.get('org') or ''), rules)
        if hit:
            stats['org_excluded'] += 1
            continue

        # ---- 探活结果，探不到的直接剔除 ----
        hx = httpx_by_key.get(probe_key) or httpx_by_key.get(ip_key)
        if not hx:
            stats['no_httpx'] += 1
            continue
        if hx.get('failed'):
            stats['bad_status'] += 1
            continue
        try:
            sc = int(hx.get('status_code') or 0)
        except (TypeError, ValueError):
            sc = 0
        if sc in (0, 502, 503):
            stats['bad_status'] += 1
            continue

        url = f'{scheme}://{probe_host}:{port}'
        title = str(hx.get('title') or '')
        webserver = str(hx.get('webserver') or '')
        fofa_server = str(item.get('server') or '')
        tech = hx.get('tech') if isinstance(hx.get('tech'), list) else []

        # ---- 版本证据 + 三态判断 ----
        versions = collect_versions(product, webserver, fofa_server, tech,
                                    str(item.get('header') or ''))
        extracted_version = versions[0]['version'] if versions else None
        version_status = version_compare.compare(extracted_version,
                                                 affected_ranges, excluded_versions)
        if version_status == 'unaffected':
            stats['version_unaffected'] += 1
            continue

        # ---- match_score：只有它决定排序和门槛 ----
        fofa_hit = fofa_title_hit(product, fingerprint, item.get('title'))
        if fofa_hit:
            stats['fofa_title_hit'] += 1
        match_score = 0
        reasons = []
        if tech_hit(product, tech):
            match_score += 30
            reasons.append('httpx tech 命中产品')
        if fofa_hit:
            match_score += 30
            reasons.append('FOFA标题命中产品')
        if title.strip():
            match_score += 20
            reasons.append('httpx标题非空')
        elif fofa_hit:
            match_score += 20
            reasons.append('标题证据(FOFA)')
        if versions:
            match_score += 30
            reasons.append(f'有可靠版本号:{extracted_version}')
        if version_status == 'affected':
            match_score += 20
            reasons.append('版本落在影响范围')

        # ---- 可达性成本：不参与 match_score ----
        # CDN 与 WAF 严格分开：httpx 的 cdn 字段归 is_cdn（此前误归 is_waf，
        # 会让纯 CDN 目标被标成 cdn+waf，成本翻倍且提示失真）
        # cdncheck 的 input 是裸主机名（无端口），裸键必须一起试
        cd = (cdn_by_key.get(probe_key)
              or cdn_by_key.get(norm_key(probe_host))
              or cdn_by_key.get(ip_key)
              or cdn_by_key.get(norm_key(ip))) or {}
        waf_row = (waf_by_key.get(probe_key) or waf_by_key.get(ip_key)) or {}
        is_cdn = bool(cd.get('cdn')) or bool(cd.get('cdn_name')) or bool(hx.get('cdn'))
        is_waf = bool(waf_row.get('detected')) or bool(cd.get('waf'))
        if is_cdn and is_waf:
            reachability = 'cdn+waf'
        elif is_cdn:
            reachability = 'cdn'
        elif is_waf:
            reachability = 'waf'
        else:
            reachability = 'direct'
        if is_cdn:
            reasons.append('CDN目标')
        if is_waf:
            reasons.append('检测到WAF')

        stats['scored'] += 1
        targets.append({
            'ip': ip,
            'port': int(port) if port.isdigit() else port,
            'url': url,
            'title': title,
            'server': webserver or fofa_server,
            'status_code': sc,
            'matched_fingerprint': fingerprint,
            'extracted_version': extracted_version,
            'versions': versions,
            'version_status': version_status,
            'cdn': is_cdn,
            'waf': is_waf,
            'cdn_provider': cd.get('cdn_name') or hx.get('cdn_name') or '',
            'waf_provider': cd.get('waf_name') or waf_row.get('firewall') or '',
            'reachability': reachability,
            'verification_cost': VERIFICATION_COST[reachability],
            'match_score': match_score,
            'classification': classify(match_score, version_status),
            'reasons': reasons,
            'verify_hint': build_hint(is_waf, version_status, verify_path),
        })

    # 去重（同键保留 match_score 最高的一条）
    dedup = {}
    for t in sorted(targets, key=lambda x: -x['match_score']):
        dedup.setdefault(f"{t['ip']}:{t['port']}", t)
    deduped = list(dedup.values())

    kept = [t for t in deduped if t['match_score'] >= args.min_score]
    stats['below_score'] = len(deduped) - len(kept)
    kept.sort(key=lambda x: (-x['match_score'], x['verification_cost']))
    if len(kept) > args.limit:
        stats['truncated'] = True
        kept = kept[:args.limit]
    stats['final'] = len(kept)

    out_path = os.path.abspath(args.output)
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    txt_path = os.path.splitext(out_path)[0] + '.txt'
    csv_path = os.path.splitext(out_path)[0] + '.csv'

    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(kept, f, ensure_ascii=False, indent=2)
    with open(txt_path, 'w', encoding='utf-8', newline='\n') as f:
        for t in kept:
            f.write(t['url'] + '\n')
    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'port', 'url', 'title', 'server', 'version',
                    'match_score', 'reachability'])
        for t in kept:
            w.writerow([t['ip'], t['port'], t['url'], t['title'], t['server'],
                        t['extracted_version'] or '', t['match_score'],
                        t['reachability']])

    print(f"raw={stats['raw']}")
    print(f"out_of_scope={stats['out_of_scope']}")
    print(f"org_excluded={stats['org_excluded']}")
    print(f"no_httpx={stats['no_httpx']}")
    print(f"bad_status={stats['bad_status']}")
    print(f"version_unaffected={stats['version_unaffected']}")
    print(f"fofa_title_hit={stats['fofa_title_hit']}")
    print(f"scored={stats['scored']}")
    print(f"deduped={len(deduped)}")
    print(f"below_score={stats['below_score']}")
    print(f"final={stats['final']}")
    print(f"truncated={stats['truncated']}")
    cls = {}
    for t in kept:
        cls[t['classification']] = cls.get(t['classification'], 0) + 1
    print('classification: ' + ' '.join(f'{k}={v}' for k, v in sorted(cls.items())))
    print(f"output={out_path}")
    print(f"txt={txt_path}")
    print(f"csv={csv_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())

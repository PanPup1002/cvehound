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
              matched_fingerprint / verify_path / verify_path_inferred /
              fofa_query / fofa_total / run_mode / country_mode）
  --version-probe  可选：version_probe.py 输出 JSONL
  --output    目标清单输出路径（.json）；同目录同名 .txt / .csv 一并写出
  --scope     可选授权范围 JSON（tools/scope.py 格式）；提供时强制剔除范围外资产
  --selection stratified|top  截断选择策略（默认 stratified）
  --skip-reachability         不把 cdn/waf 视为已测

输出
  {output}.json  全字段目标列表（按 tier/score/cost 排序）
  {output}.txt   每行一个 URL（显式 LF 行尾）
  {output}.csv   ip,port,url,title,server,version,match_score,reachability,
                 classification,confidence_tier,version_status,country,cdn,waf,verify_path
                 （前 8 列与旧版一致；utf-8-sig）
  {CVE}_coverage.json  覆盖率、截断原因、tier/国家分布

评分模型（v2，满分 clamp 100）
  +30  FOFA app= / cert= / header= 指纹引擎命中（强 cohort）
  +40  httpx tech[] 命中 product（强独立）
  +30  server / X-Powered-By 命中 product（强独立）
  +25  有可靠版本号（version_probe > httpx_tech > server > fofa）
  +25  version_status == "affected"
  +10  标题命中产品（live httpx title；弱）
  +10  FOFA 标题命中，且查询不是 title= 类
   0  仅"标题非空"；title="X" 查询的标题命中（自证）
  CDN/WAF 不参与 match_score，只影响可达性成本；缺失记 not_tested。

交付分级（confidence_tier）
  A = version_status == affected
  B = 非 A 且存在强独立证据（tech 或 server 命中）
  C = 其余（仅弱证据）

分类（四档）
    likely_affected    ≥80 且 version_status == "affected"
    probable           ≥60
    needs_verification ≥40（默认输出门槛，--min-score 可调）
    rejected           <40，不输出

  reachability      direct / waf / cdn / cdn+waf / not_tested
  verification_cost direct=10, waf=30, cdn=40, cdn+waf=60, not_tested=null

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
import hashlib
import json
import os
import re
import sys
import time

import probe_inputs
import scope as scope_mod
import version_compare

VER_RE = re.compile(r'\d+(?:\.\d+){1,2}')

# versions 证据各来源的可信度
SOURCE_RELIABILITY = {
    'version_probe': 0.95,
    'httpx_tech': 0.90,
    'webserver_header': 0.85,
    'fofa_server': 0.80,
    'x_powered_by': 0.80,
    'response_body': 0.60,
    'cookie': 0.50,
}

VERIFICATION_COST = {'direct': 10, 'waf': 30, 'cdn': 40, 'cdn+waf': 60}

# 证据权重。满分 clamp 到 100（此前实际可到 130，文档却写 0-100）。
# 关键：标题只是弱证据；tech/server 才是独立于 FOFA 查询的产品证据。
EVIDENCE_WEIGHTS = {
    'cohort': 30,       # FOFA app=/cert=/header= 指纹引擎命中
    'cohort_path': 40,  # body= 命中具体资源路径（如 /wp-content/plugins/<slug>/）
    'tech': 40,         # httpx tech[] 命中产品
    'server': 30,       # server / X-Powered-By 命中产品（强独立）
    'version': 25,      # 任一可靠版本号
    'affected': 25,     # 版本落在影响区间
    'title': 10,        # 标题命中产品
}

# app=/cert=/header=/title= 由 FOFA 的指纹/标题字段匹配产品身份；
# 其中 title= 的自证性最强，但对 DAP-1360 这类"标题即产品型号"的设备是唯一
# 可用信号，因此仍计 cohort 分；普通 body= 文本关键词仍视为查询自证。
# title= 的 cohort 分要求 live httpx 标题也命中（见评分逻辑），避免只凭索引。
COHORT_EVIDENCE_KINDS = ('app', 'cert', 'header', 'title')
MAX_MATCH_SCORE = 100

# 负向词：hard 命中标题即把 tier 封顶为 C；soft/gray 只扣分。
NEGATIVE_PENALTY = {'hard': 15, 'soft': 6, 'gray': 6}
NEGATIVE_CAP = 30
DEFAULT_FINGERPRINT_RULES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'fingerprint_rules.json')

# 指纹类型：title="X" 是查询自证——FOFA 查询本身要求标题含 X，
# 再把 "FOFA 标题命中" 当独立证据会让每条结果自动拿满标题分。
_FP_KIND_RE = re.compile(r'^\s*([a-zA-Z_]+)\s*=')

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


def fingerprint_needles(fingerprint):
    """从指纹中提取可参与标题匹配的值。
    `cert="Ahsay"` -> ['cert="Ahsay"', 'Ahsay']；纯字符串原样返回。"""
    s = str(fingerprint or '').strip()
    needles = [s] if s else []
    for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'', s):
        v = (m.group(1) or m.group(2) or '').strip()
        if v and v not in needles:
            needles.append(v)
    return needles


def fofa_title_hit(product, fingerprint, title):
    """FOFA 标题是否命中产品（或匹配指纹）。指纹库盲区通道：wappalyzer 没有
    该产品指纹时（框架类 CVE），FOFA 抓到的页面标题若显式点名产品
    （如「系统登录 · ThinkAdmin」），就是可靠的产品证据。
    子串匹配（小写化）；先试 product，再回退 matched_fingerprint——
    多词产品的标题通常只写短名（"Apache Log4j2" 的页面只写 "Log4j2"）。"""
    t = str(title or '').lower()
    if not t:
        return False
    for needle in [product] + fingerprint_needles(fingerprint):
        n = str(needle or '').strip().lower()
        if n and n in t:
            return True
    return False


# 平台/依赖词：单独出现时不能被当成某个多词产品的身份。
# 典型误判：产品 "Unlimited Elements For Elementor" 被 tech "Elementor" 命中，
# 把 Elementor 的版本记到插件头上（实测导致 1078 条错误 unaffected）。
PLATFORM_TECH_WORDS = {
    'elementor', 'wordpress', 'woocommerce', 'joomla', 'drupal', 'shopify',
    'bootstrap', 'jquery', 'react', 'vue', 'angular', 'laravel', 'django',
    'rails', 'spring', 'magento', 'prestashop', 'divi', 'astra', 'oceanwp',
}


def _tech_name_matches(product, name):
    """tech 条目名与产品名是否指同一产品。
    规则：
      1. 归一化后完全相同 -> 命中；
      2. 产品名含 for/by/with 时，只取分隔词之前的主体
         （"Unlimited Elements For Elementor" -> "unlimited elements"）；
      3. 单 token 的平台词（Elementor/WordPress 等）单独命中不算，
         除非它本身就是产品主体的一部分；
      4. 其余按词首匹配（"log4j" 命中 "log4j2"，"php" 命中不了 "thinkphp"）。
    """
    prod = _norm_prod(product).split()
    nm = _norm_prod(name).split()
    if not prod or not nm:
        return False
    if prod == nm:
        return True
    for sep in ('for', 'by', 'with'):
        if sep in prod:
            prod = prod[:prod.index(sep)]
            break
    if not prod:
        return False
    if len(nm) == 1 and nm[0] in PLATFORM_TECH_WORDS:
        return False
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


def build_hint(is_waf, version_status, verify_path, verify_path_inferred=False):
    """verify_hint 按优先级生成。verify_path 为空是常态，退回通用说法，不报错。
    措辞保持中性（「授权范围内人工核验」）——不出现「绕过 WAF」这类
    不适合作为默认自动化建议的表述。

    verify_path 非空时**所有分支**都追加——尤其 unknown 分支最需要它：
    版本拿不到正是要人工去看的时候（此前只在 affected 分支追加，导致
    框架/库类 CVE 的候选池几乎永远拿不到验证路径）。

    verify_path_inferred=True 时追加「（推测，需确认）」标记：该路径不是从
    references / 公开 PoC 实证得来，而是按框架约定推断的。必须让用户一眼
    看出区别——否则推断值会以肯定语气呈现，比留空更误导。"""
    if verify_path:
        mark = '（推测，需确认）' if verify_path_inferred else ''
        suffix = f'；建议验证路径: {verify_path}{mark}'
    else:
        suffix = ''
    if version_status == 'affected':
        if is_waf:
            return '版本命中影响范围；存在WAF，人工核验时留意WAF拦截' + suffix
        return '版本命中影响范围，建议在授权范围内人工核验' + suffix
    if is_waf:
        return '需手动确认指纹后再核验（存在WAF）' + suffix
    return '需手动确认指纹后再核验' + suffix


def classify(match_score, version_status, tier=None):
    """四档分类（改进方案 §9.2）。
    likely_affected 需要 tier A：版本命中且版本证据可信度 >= 0.8；
    低可信度的通用页面正则即使落在区间内，也只到 B/probable。"""
    if tier is None:
        tier = 'A' if version_status == 'affected' else 'B'
    if match_score >= 80 and version_status == 'affected' and tier == 'A':
        return 'likely_affected'
    if match_score >= 60:
        return 'probable'
    if match_score >= 40:
        return 'needs_verification'
    return 'rejected'


def fingerprint_kind(fingerprint):
    """从 matched_fingerprint 提取查询类型：app/title/body/cert/header/unknown。"""
    m = _FP_KIND_RE.match(str(fingerprint or ''))
    return m.group(1).lower() if m else 'unknown'


def fofa_title_is_independent(fingerprint):
    """查询不是 title= 时，FOFA 标题命中才是独立于查询的证据。
    title="X" 类查询的标题命中是自证，不能计分。"""
    return fingerprint_kind(fingerprint) != 'title'


def negative_hits(text, rules):
    """返回命中的负向词列表 [{term, severity}]。
    ASCII 用词边界（避免 news 命中 newsroom 之外的东西），中文用子串。"""
    t = str(text or '').lower()
    if not t:
        return []
    out = []
    generic = (rules or {}).get('generic_negative') or {}
    for severity in ('hard', 'soft', 'gray'):
        for term in generic.get(severity) or []:
            term_l = str(term).lower().strip()
            if not term_l:
                continue
            if term_l.isascii():
                if re.search(r'\b' + re.escape(term_l) + r'\b', t):
                    out.append({'term': term, 'severity': severity})
            elif term_l in t:
                out.append({'term': term, 'severity': severity})
    return out


def cohort_evidence_kind(fingerprint):
    """返回 cohort 证据类型：app/cert/header/body-path，无则空串。
    body= 只有命中具体资源路径（含 "/"）才算结构性证据；
    普通文本关键词（如 body="flowsint"）仍视为查询自证。"""
    kind = fingerprint_kind(fingerprint)
    if kind in COHORT_EVIDENCE_KINDS:
        return kind
    if kind == 'body':
        for needle in fingerprint_needles(fingerprint):
            n = needle.strip()
            if ('/' in n and len(n) > 8) or re.match(
                    r'^(?:com|mod|plg)_[a-z0-9_]+$', n, re.I):
                return 'body-path'
    return ''


def classify_tier(version_status, has_strong_evidence, best_reliability=1.0):
    """交付分级：A=版本命中（需较强版本证据）；B=强独立证据但版本未知；
    C=仅弱证据。低可信度的通用版本提取（如页面正则）最高只到 B。"""
    if version_status == 'affected':
        try:
            reliable = float(best_reliability) >= 0.8
        except (TypeError, ValueError):
            reliable = False
        return 'A' if reliable else 'B'
    if has_strong_evidence:
        return 'B'
    return 'C'


def server_product_hit(product, webserver, fofa_server, header):
    """server / X-Powered-By 是否点名了产品（词首匹配，避免 PHP↔ThinkPHP）。"""
    if not str(product or '').strip():
        return False
    for text in (webserver, fofa_server):
        text = str(text or '').strip()
        if not text:
            continue
        token = text.split('(')[0].split('/')[0].strip()
        token = token.split()[0] if token.split() else ''
        if token and _tech_name_matches(product, token):
            return True
    for line in str(header or '').splitlines():
        if line.lower().startswith('x-powered-by:'):
            val = line.split(':', 1)[1].strip() if ':' in line else ''
            token = val.split('/')[0].strip()
            if token and _tech_name_matches(product, token):
                return True
    return False


def merge_versions(*version_lists):
    """合并多组版本证据，按 (source, version) 去重，可信度降序。"""
    seen = {}
    for lst in version_lists:
        for v in lst or []:
            key = (v.get('source'), v.get('version'))
            if key not in seen:
                seen[key] = v
    return sorted(seen.values(), key=lambda x: -float(x.get('reliability') or 0))


def probe_versions_for(probe_rows, product):
    """把 version_probe 输出转成 versions 证据。
    probe_rows 是同一目标的多条探测记录（可能为空）。
    可信度使用探测记录里的 confidence（通用页面正则低、专用端点高），
    不再一律按 0.95 处理。"""
    out = []
    for row in probe_rows or []:
        ver = str(row.get('version') or '').strip()
        if not ver or version_compare.parse_version(ver) is None:
            continue
        try:
            reliability = float(row.get('confidence'))
        except (TypeError, ValueError):
            reliability = SOURCE_RELIABILITY['version_probe']
        reliability = max(0.0, min(1.0, reliability))
        out.append({'product': product, 'version': ver,
                    'source': 'version_probe',
                    'reliability': reliability})
    return out


def _clip(value, limit=200):
    s = str(value or '')
    return s[:limit] + ('…' if len(s) > limit else '')


def build_evidence(item, hx, versions, version_status, tested,
                   is_cdn, is_waf, providers):
    """目标级证据包：只保留判断所需字段，截断长度，不保存 body/完整 header。"""
    tech = hx.get('tech') if isinstance(hx.get('tech'), list) else []
    return {
        'fofa': {
            'title': _clip(item.get('title')),
            'server': _clip(item.get('server')),
            'org': _clip(item.get('org')),
            'country': _clip(item.get('country')),
        },
        'httpx': {
            'status': hx.get('status_code'),
            'title': _clip(hx.get('title')),
            'server': _clip(hx.get('webserver')),
            'tech': [_clip(t, 60) for t in tech[:20]],
            'final_url': _clip(hx.get('url'), 300),
        },
        'version': {
            'status': version_status,
            'matches': versions[:5],
        },
        'reachability': {
            'tested': bool(tested),
            'cdn': bool(is_cdn),
            'waf': bool(is_waf),
            'providers': providers,
        },
    }


def build_verify_commands(url, verify_path, product, affected_ranges):
    """生成可执行的核验命令（只给 GET 模板，不含攻击载荷）。"""
    cmds = []
    if verify_path:
        p = verify_path if verify_path.startswith('/') else '/' + verify_path
        cmds.append({
            'label': '建议验证路径',
            'method': 'GET',
            'url': url.rstrip('/') + p,
            'expect': '按漏洞公告核验响应',
        })
    if affected_ranges:
        parts = []
        for r in affected_ranges[:3]:
            start = r.get('start') or '-∞'
            end = r.get('end') or '+∞'
            op = '<=' if r.get('end_inclusive') else '<'
            parts.append(f'{start} <= v {op} {end}')
        cmds.append({
            'label': '版本判定',
            'method': 'GET',
            'url': url.rstrip('/'),
            'expect': f'确认 {product} 版本满足: ' + '; '.join(parts),
        })
    return cmds


def _stable_hash(text):
    return hashlib.sha256(str(text).encode('utf-8')).hexdigest()


def _cost_key(target):
    cost = target.get('verification_cost')
    return cost if cost is not None else 10 ** 9


def _stratified_pick(candidates, limit):
    """确定性的分层抽样：按 (tier, score, country) 分组，组内哈希排序、组间轮转。
    避免同分时"任意取前 100"；同一输入永远得到同一集合。"""
    groups = {}
    for t in candidates:
        key = (t.get('confidence_tier', 'C'), t.get('match_score', 0),
               t.get('country') or '??')
        groups.setdefault(key, []).append(t)
    for g in groups.values():
        g.sort(key=lambda x: _stable_hash(f"{x.get('ip')}:{x.get('port')}"))
    tier_rank = {'A': 0, 'B': 1, 'C': 2}
    keys = sorted(groups, key=lambda k: (tier_rank.get(k[0], 9), -k[1], k[2]))
    out = []
    while len(out) < limit:
        progressed = False
        for k in keys:
            if groups[k] and len(out) < limit:
                out.append(groups[k].pop(0))
                progressed = True
        if not progressed:
            break
    return out


def select_targets(candidates, min_score, limit, selection='stratified'):
    """过滤门槛、排序、截断。返回 (kept, below_score, truncated, reason)。"""
    kept = [t for t in candidates if t['match_score'] >= min_score]
    below = len(candidates) - len(kept)
    if len(kept) <= limit:
        kept.sort(key=lambda x: (-x['match_score'], _cost_key(x)))
        return kept, below, False, ''
    if selection == 'top':
        kept.sort(key=lambda x: (-x['match_score'], _cost_key(x)))
        return kept[:limit], below, True, f'top-{limit}: 同分按输入顺序截断'
    picked = _stratified_pick(kept, limit)
    tier_rank = {'A': 0, 'B': 1, 'C': 2}
    picked.sort(key=lambda x: (tier_rank.get(x.get('confidence_tier'), 9),
                               -x['match_score'],
                               _stable_hash(f"{x.get('ip')}:{x.get('port')}")))
    return picked, below, True, f'stratified-{limit}: 按 tier/国家确定性抽样'



def evaluate_rows(raw, httpx_items, cdn_items, waf_rows, context, rules,
                  scope=None, min_score=40, limit=100, selection='stratified',
                  version_probe_rows=None, cdn_tested=False, waf_tested=False,
                  fingerprint_rules=None):
    """纯函数式评分：给定输入返回 (kept, stats)。
    score.py 与 prefilter.py 共用，避免维护两套评分逻辑。"""
    if scope:
        raw, out_of_scope = scope_mod.filter_rows(raw, scope)
    else:
        out_of_scope = 0

    product = str(context.get('product', '')).strip()
    affected_ranges = version_compare.select_ranges(context)
    excluded_versions = context.get('excluded_versions') or []
    fingerprint = str(context.get('matched_fingerprint', '')).strip()
    fp_kind = fingerprint_kind(fingerprint)
    verify_path = str(context.get('verify_path', '')).strip()
    verify_path_inferred = bool(context.get('verify_path_inferred'))

    # httpx 索引：键 = input（原样回显探活输入行 host:port）
    httpx_by_key = {}
    for row in httpx_items:
        key = norm_key(row.get('input') or row.get('url'))
        if key and key not in httpx_by_key:
            httpx_by_key[key] = row

    # cdncheck 索引：非命中目标没有输出行，缺席 = 不是 CDN/WAF
    cdn_by_key = {}
    for row in cdn_items or []:
        key = norm_key(row.get('input'))
        if key:
            cdn_by_key[key] = row

    # wafw00f 索引：每个输入都有输出，url 带 scheme
    waf_by_key = {}
    for row in waf_rows or []:
        key = norm_key(row.get('url'))
        if key:
            waf_by_key[key] = row

    # 主动版本探测索引：同一目标可能有多条探测记录
    probe_by_key = {}
    for row in version_probe_rows or []:
        if not isinstance(row, dict):
            continue
        key = norm_key(row.get('input') or row.get('url'))
        if key:
            probe_by_key.setdefault(key, []).append(row)

    stats = {'raw': len(raw), 'out_of_scope': out_of_scope, 'skipped': 0,
             'org_excluded': 0, 'no_httpx': 0, 'bad_status': 0,
             'version_unaffected': 0, 'scored': 0, 'fofa_title_hit': 0,
             'below_score': 0, 'final': 0, 'truncated': False,
             'truncation_reason': '', 'not_tested': 0,
             'by_tier': {}, 'by_country': {}, 'reachability_tested':
             bool(cdn_tested and waf_tested)}

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
        header = str(item.get('header') or '')
        tech = hx.get('tech') if isinstance(hx.get('tech'), list) else []

        # ---- 版本证据：被动采集 + 主动探测 ----
        versions = collect_versions(product, webserver, fofa_server, tech, header)
        probe_rows = probe_by_key.get(probe_key) or probe_by_key.get(ip_key) or []
        versions = merge_versions(versions, probe_versions_for(probe_rows, product))
        extracted_version = versions[0]['version'] if versions else None
        version_status = version_compare.compare(extracted_version,
                                                 affected_ranges, excluded_versions)
        if version_status == 'unaffected':
            stats['version_unaffected'] += 1
            continue

        # ---- 证据独立性 ----
        tech_ok = tech_hit(product, tech)
        server_ok = server_product_hit(product, webserver, fofa_server, header)
        fofa_hit = fofa_title_hit(product, fingerprint, item.get('title'))
        live_title_hit = bool(title.strip()) and fofa_title_hit(
            product, fingerprint, title)
        if fofa_hit:
            stats['fofa_title_hit'] += 1

        # ---- 负向词：标题/页面标题里的 blog/docs/marketing 等 ----
        neg = negative_hits(
            f"{item.get('title') or ''} {title}", fingerprint_rules)
        penalty = min(NEGATIVE_CAP,
                      sum(NEGATIVE_PENALTY.get(n['severity'], 0) for n in neg))
        hard_negative = any(n['severity'] == 'hard' for n in neg)

        # ---- match_score：独立性加权，clamp 100 ----
        match_score = 0
        reasons = []
        strong_evidence = False
        cohort_kind = cohort_evidence_kind(fingerprint)
        # title= 查询的 cohort 分要求 live 标题也命中（避免只凭 FOFA 索引）；
        # body-path 是结构性安装证据；app/cert/header 由指纹引擎匹配。
        cohort_ok = bool(cohort_kind) and (
            cohort_kind != 'title' or live_title_hit)
        if cohort_ok:
            weight_key = 'cohort_path' if cohort_kind == 'body-path' else 'cohort'
            match_score += EVIDENCE_WEIGHTS[weight_key]
            strong_evidence = True
            reasons.append(f'FOFA {cohort_kind} 证据命中')
        if tech_ok:
            match_score += EVIDENCE_WEIGHTS['tech']
            strong_evidence = True
            reasons.append('httpx tech 命中产品')
        if server_ok:
            match_score += EVIDENCE_WEIGHTS['server']
            strong_evidence = True
            reasons.append('server/header 命中产品')
        if live_title_hit:
            match_score += EVIDENCE_WEIGHTS['title']
            reasons.append('httpx 标题命中产品')
        elif fofa_hit and fofa_title_is_independent(fingerprint):
            match_score += EVIDENCE_WEIGHTS['title']
            reasons.append('FOFA 标题命中产品（查询非标题类）')
        elif fofa_hit:
            reasons.append('FOFA 标题命中（title= 查询自证，不计分）')
        if versions:
            match_score += EVIDENCE_WEIGHTS['version']
            reasons.append(f'有可靠版本号:{extracted_version}')
        if version_status == 'affected':
            match_score += EVIDENCE_WEIGHTS['affected']
            reasons.append('版本落在影响范围')
        match_score = max(0, min(MAX_MATCH_SCORE, match_score - penalty))
        if neg:
            reasons.append('负向词:' + ','.join(n['term'] for n in neg[:5]))

        best_reliability = versions[0]['reliability'] if versions else 0.0
        tier = classify_tier(version_status, strong_evidence, best_reliability)
        if hard_negative:
            tier = 'C'

        # ---- 可达性成本：缺测时绝不默认 direct ----
        cd = (cdn_by_key.get(probe_key)
              or cdn_by_key.get(norm_key(probe_host))
              or cdn_by_key.get(ip_key)
              or cdn_by_key.get(norm_key(ip))) or {}
        waf_row = (waf_by_key.get(probe_key) or waf_by_key.get(ip_key)) or {}
        is_cdn = bool(cd.get('cdn')) or bool(cd.get('cdn_name')) or bool(hx.get('cdn'))
        is_waf = bool(waf_row.get('detected')) or bool(cd.get('waf'))
        tested = bool(cdn_tested and waf_tested)
        if tested:
            if is_cdn and is_waf:
                reachability = 'cdn+waf'
            elif is_cdn:
                reachability = 'cdn'
            elif is_waf:
                reachability = 'waf'
            else:
                reachability = 'direct'
            verification_cost = VERIFICATION_COST[reachability]
        else:
            reachability = 'not_tested'
            verification_cost = None
        if is_cdn:
            reasons.append('CDN目标')
        if is_waf:
            reasons.append('检测到WAF')
        providers = []
        for p in (cd.get('cdn_name'), cd.get('waf_name'), waf_row.get('firewall')):
            if p and str(p).strip().lower() not in ('none', 'null', ''):
                providers.append(str(p))

        stats['scored'] += 1
        targets.append({
            'ip': ip,
            'port': int(port) if str(port).isdigit() else port,
            'url': url,
            'title': title,
            'server': webserver or fofa_server,
            'status_code': sc,
            'country': str(item.get('country') or '').strip(),
            'matched_fingerprint': fingerprint,
            'fingerprint_kind': fp_kind,
            'extracted_version': extracted_version,
            'versions': versions,
            'version_status': version_status,
            'cdn': is_cdn,
            'waf': is_waf,
            'cdn_provider': cd.get('cdn_name') or hx.get('cdn_name') or '',
            'waf_provider': cd.get('waf_name') or waf_row.get('firewall') or '',
            'reachability': reachability,
            'reachability_tested': tested,
            'verification_cost': verification_cost,
            'match_score': match_score,
            'confidence_tier': tier,
            'negative_hits': neg,
            'score_penalty': -penalty,
            'classification': classify(match_score, version_status, tier),
            'reasons': reasons,
            'evidence': build_evidence(item, hx, versions, version_status,
                                       tested, is_cdn, is_waf, providers),
            'verify_commands': build_verify_commands(
                url, verify_path, product, affected_ranges),
            'verify_path': verify_path,
            'verify_path_inferred': verify_path_inferred,
            'verify_hint': build_hint(is_waf, version_status, verify_path,
                                      verify_path_inferred),
        })

    # 去重（同键保留 match_score 最高的一条）
    dedup = {}
    for t in sorted(targets, key=lambda x: (-x['match_score'], _cost_key(x))):
        dedup.setdefault(f"{t['ip']}:{t['port']}", t)
    deduped = list(dedup.values())
    stats['deduped'] = len(deduped)

    kept, below, truncated, reason = select_targets(
        deduped, min_score, limit, selection)
    stats['below_score'] = below
    stats['truncated'] = truncated
    stats['truncation_reason'] = reason
    stats['final'] = len(kept)
    for t in kept:
        tier = t.get('confidence_tier', 'C')
        stats['by_tier'][tier] = stats['by_tier'].get(tier, 0) + 1
        country = t.get('country') or '??'
        stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
        if t.get('reachability') == 'not_tested':
            stats['not_tested'] += 1
    return kept, stats


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
    ap.add_argument('--version-probe', default=None,
                    help='可选：version_probe.py 输出 JSONL')
    ap.add_argument('--min-score', type=int, default=40)
    ap.add_argument('--limit', type=int, default=100)
    ap.add_argument('--selection', choices=('stratified', 'top'),
                    default='stratified',
                    help='截断选择策略；top 保留旧的按分数取前 N')
    ap.add_argument('--skip-reachability', action='store_true',
                    help='不把 cdn/waf 视为已测；reachability 记为 not_tested')
    ap.add_argument('--exclude',
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         'exclude_keywords.json'))
    ap.add_argument('--fingerprint-rules', default=DEFAULT_FINGERPRINT_RULES,
                    help='负向词表 fingerprint_rules.json')
    args = ap.parse_args()

    raw = load_required_json(args.raw, 'raw 导出')
    if isinstance(raw, dict):
        raw = raw.get('results') or raw.get('data')
    if not isinstance(raw, list):
        _die('raw 结构无法识别（既不是数组也不是 {"results":[...]}）')
    context = load_required_json(args.context, 'context 情报')
    rules = load_json(args.exclude, default={})
    fingerprint_rules = load_json(args.fingerprint_rules, default={})

    # httpx 是必需输入；cdn / waf 是可选输入
    httpx_items, httpx_bad, httpx_sample = load_jsonl(args.httpx)
    if httpx_items is None:
        _die(f'httpx 输出不存在: {args.httpx}')
    if httpx_bad:
        print(f'[warn] httpx 输出有 {httpx_bad} 行损坏（{httpx_sample}）',
              file=sys.stderr)
    if not httpx_items and httpx_bad:
        _die('httpx 输出全部损坏，无法评分')

    cdn_items, cdn_bad, cdn_sample = load_jsonl(args.cdn)
    cdn_tested = cdn_items is not None
    if cdn_items is None:
        print('[warn] cdn 输入缺失：reachability 记为 not_tested', file=sys.stderr)
        cdn_items = []
    if cdn_bad:
        print(f'[warn] cdn 输出有 {cdn_bad} 行损坏（{cdn_sample}）', file=sys.stderr)

    waf_tested = os.path.exists(args.waf)
    if not waf_tested:
        print('[warn] waf 输入缺失：reachability 记为 not_tested', file=sys.stderr)
    waf_rows = load_json(args.waf, default=[])
    if isinstance(waf_rows, dict):
        waf_rows = waf_rows.get('results') or waf_rows.get('data') or []

    version_probe_rows = []
    if args.version_probe:
        version_probe_rows, vp_bad, vp_sample = load_jsonl(args.version_probe)
        if version_probe_rows is None:
            print(f'[warn] version probe 不存在: {args.version_probe}',
                  file=sys.stderr)
            version_probe_rows = []
        if vp_bad:
            print(f'[warn] version probe 有 {vp_bad} 行损坏（{vp_sample}）',
                  file=sys.stderr)

    if args.skip_reachability:
        cdn_tested = False
        waf_tested = False

    scope = None
    if args.scope:
        try:
            scope = scope_mod.load_scope(args.scope)
        except scope_mod.ScopeError as e:
            _die(str(e), 3)

    kept, stats = evaluate_rows(
        raw, httpx_items, cdn_items, waf_rows, context, rules, scope=scope,
        min_score=args.min_score, limit=args.limit, selection=args.selection,
        version_probe_rows=version_probe_rows, cdn_tested=cdn_tested,
        waf_tested=waf_tested, fingerprint_rules=fingerprint_rules)

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
                    'match_score', 'reachability', 'classification',
                    'confidence_tier', 'version_status', 'country', 'cdn',
                    'waf', 'verify_path'])
        for t in kept:
            w.writerow([t['ip'], t['port'], t['url'], t['title'], t['server'],
                        t['extracted_version'] or '', t['match_score'],
                        t['reachability'], t['classification'],
                        t['confidence_tier'], t['version_status'],
                        t.get('country') or '', t['cdn'], t['waf'],
                        (t.get('verify_path') or '')
                        + ('（推测，需确认）' if t.get('verify_path_inferred')
                           and t.get('verify_path') else '')])

    print(f"raw={stats['raw']}")
    print(f"out_of_scope={stats['out_of_scope']}")
    print(f"org_excluded={stats['org_excluded']}")
    print(f"no_httpx={stats['no_httpx']}")
    print(f"bad_status={stats['bad_status']}")
    print(f"version_unaffected={stats['version_unaffected']}")
    print(f"fofa_title_hit={stats['fofa_title_hit']}")
    print(f"scored={stats['scored']}")
    print(f"deduped={stats['deduped']}")
    print(f"below_score={stats['below_score']}")
    print(f"final={stats['final']}")
    print(f"truncated={stats['truncated']}")
    print(f"truncation_reason={stats['truncation_reason']}")
    print(f"reachability_tested={stats['reachability_tested']}")
    print(f"not_tested={stats['not_tested']}")
    print('tiers: ' + ' '.join(f'{k}={v}' for k, v in sorted(stats['by_tier'].items())))
    print('countries: ' + ' '.join(
        f'{k}={v}' for k, v in sorted(stats['by_country'].items(),
                                      key=lambda kv: -kv[1])))
    cls = {}
    for t in kept:
        cls[t['classification']] = cls.get(t['classification'], 0) + 1
    print('classification: ' + ' '.join(f'{k}={v}' for k, v in sorted(cls.items())))
    print(f"output={out_path}")
    print(f"txt={txt_path}")
    print(f"csv={csv_path}")

    # 覆盖率 sidecar：显式记录覆盖比例与截断原因，避免"看起来是全集"
    base = os.path.splitext(out_path)[0]
    if base.endswith('_targets'):
        coverage_path = base[:-len('_targets')] + '_coverage.json'
    else:
        coverage_path = base + '_coverage.json'
    if coverage_path:
        coverage = {
            'schema_version': 1,
            'cve_id': context.get('cve_id'),
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'query': context.get('fofa_query')
            or context.get('matched_fingerprint') or '',
            'selection': args.selection,
            'min_score': args.min_score,
            'limit': args.limit,
            'stats': stats,
            'coverage_ratio_vs_export': 1.0,
        }
        total = context.get('fofa_total')
        if isinstance(total, (int, float)) and total > 0:
            coverage['fofa_total'] = total
            coverage['coverage_ratio_vs_fofa'] = round(
                stats['raw'] / total, 6)
        with open(coverage_path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(coverage, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(f"coverage={coverage_path}")
    return 0

if __name__ == '__main__':
    sys.exit(main())

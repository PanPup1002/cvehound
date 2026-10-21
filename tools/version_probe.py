"""
主动版本探测（低影响、只读 GET）

用途：产品版本通常不出现在页面标题里，导致 score.py 的 version_status 永远是
unknown。本工具按 tools/version_probes.json 的产品规则做少量 GET，从 JSON /
响应头 / HTML generator meta 中提取版本，供 score.py 的 affected 判定使用。

安全约束（硬编码，不提供开关）：
  - 只发 GET，不发任何请求体，不做认证、不做 fuzzing、不提交攻击载荷；
  - 每个目标最多尝试 --max-requests 条规则（默认 2）；
  - 只处理 --max-targets 条目标（默认 50）；
  - User-Agent 固定为 cvehound-version-probe/1.0。

用法：
  python tools/version_probe.py --targets data/CVE-XXXX_probe_urls.txt \
      --context data/CVE-XXXX_context.json \
      --table tools/version_probes.json \
      --output data/CVE-XXXX_version_probe.jsonl \
      --max-targets 50 --timeout 5 --threads 10

  python tools/version_probe.py ... --dry-run    # 只打印计划，不发请求

输出：JSONL，每行 {input,url,path,status,version,source,rule,confidence,evidence}
退出码：0 成功（部分失败也返回 0）；2 输入错误。
"""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import version_compare

UA = 'cvehound-version-probe/1.0'
_VER_RE = re.compile(r'\d+(?:\.\d+){1,3}')


def load_json(path, default=None):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as e:
        print(f'[warn] {path} JSON 损坏: {e}', file=sys.stderr)
        return default


def _norm_name(value):
    return re.sub(r'[^a-z0-9]+', ' ', str(value or '').lower()).strip()


def _name_match(product, name):
    """产品名与探测到的名字是否指同一产品（词首匹配，双向）。"""
    a = _norm_name(product).split()
    b = _norm_name(name).split()
    if not a or not b:
        return False
    if a == b:
        return True
    return any(x.startswith(y) or y.startswith(x) for x in a for y in b)


def matching_rules(product, table):
    """返回该产品的专用规则 + 通用规则（专用优先）。"""
    rules = table.get('rules') or []
    specific, generic = [], []
    for rule in rules:
        products = rule.get('products') or []
        if '*' in products:
            generic.append(rule)
        elif any(_name_match(product, p) for p in products):
            specific.append(rule)
    return specific + generic


def _json_get(data, path):
    cur = data
    for part in str(path or '').split('.'):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if 0 <= idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def extract_version(rule, status, headers, body, product):
    """按规则从响应中提取版本。返回 (version, evidence) 或 (None, '')。"""
    body = body or ''
    if rule.get('type') == 'json':
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return None, ''
        value = _json_get(data, rule.get('json_path'))
        if value is None:
            return None, ''
        m = _VER_RE.search(str(value))
        if not m:
            return None, ''
        return m.group(0), f'JSON {rule.get("json_path")} = {value!r}'

    if rule.get('type') == 'header':
        header_name = str(rule.get('header') or '').lower()
        value = ''
        for k, v in (headers or {}).items():
            if k.lower() == header_name:
                value = v
                break
        if not value:
            return None, ''
        m = re.search(rule.get('regex') or _VER_RE.pattern, value)
        if not m:
            return None, ''
        groups = m.groups()
        product_group = rule.get('product_group')
        if product_group is not None and len(groups) >= product_group:
            found_product = groups[int(product_group) - 1]
            if not _name_match(product, found_product):
                return None, ''
        version_group = rule.get('version_group')
        if version_group is not None and len(groups) >= version_group:
            ver = groups[int(version_group) - 1]
        else:
            ver = m.group(0)
        m2 = _VER_RE.search(str(ver))
        if not m2:
            return None, ''
        return m2.group(0), f'{header_name}: {value}'

    if rule.get('type') == 'readme_stable_tag':
        m = re.search(
            rule.get('regex')
            or r'Stable tag:\s*([0-9]+(?:\.[0-9]+){1,3})',
            body, re.I)
        if not m:
            return None, ''
        ver = m.group(1) if m.groups() else m.group(0)
        m2 = _VER_RE.search(str(ver))
        if not m2:
            return None, ''
        return m2.group(0), f'readme Stable tag: {m.group(0)[:120]}'

    if rule.get('type') == 'body_regex':
        m = re.search(rule.get('regex') or '', body, re.I | re.S)
        if not m:
            return None, ''
        ver = m.group(1) if m.groups() else m.group(0)
        m2 = _VER_RE.search(str(ver))
        if not m2:
            return None, ''
        return m2.group(0), f'body regex: {m.group(0)[:120]}'

    if rule.get('type') == 'body_product_version':
        product = str(product or '').strip()
        if not product:
            return None, ''
        pat = re.escape(product) + r'[^\n<>]{0,40}?([0-9]+(?:\.[0-9]+){1,3})'
        m = re.search(pat, body, re.I | re.S)
        if not m:
            return None, ''
        ver = m.group(1) if m.groups() else m.group(0)
        m2 = _VER_RE.search(str(ver))
        if not m2:
            return None, ''
        return m2.group(0), f'产品名邻近版本: {m.group(0)[:120]}'

    if rule.get('type') == 'meta_generator':
        m = re.search(rule.get('regex') or '', body, re.I | re.S)
        if not m:
            return None, ''
        ver = m.group(1) if m.groups() else m.group(0)
        m2 = _VER_RE.search(str(ver))
        if not m2:
            return None, ''
        return m2.group(0), f'meta generator: {m.group(0)[:160]}'

    return None, ''


def fetch(url, timeout=5, verify_tls=False):
    """只读 GET。返回 (status, headers_dict, body_text)。"""
    ctx = None
    if url.lower().startswith('https') and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method='GET', headers={
        'User-Agent': UA, 'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read(256 * 1024)
        charset = resp.headers.get_content_charset() or 'utf-8'
        body = raw.decode(charset, errors='replace')
        return resp.status, dict(resp.headers.items()), body


def probe_one(base_url, rules, timeout, verify_tls, max_requests):
    records = []
    if not base_url.lower().startswith(('http://', 'https://')):
        return records
    for rule in rules[:max_requests]:
        path = rule.get('path') or '/'
        url = base_url.rstrip('/') + path
        try:
            status, headers, body = fetch(url, timeout, verify_tls)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                OSError, ValueError):
            continue
        version, evidence = extract_version(
            rule, status, headers, body, rule.get('_product', ''))
        if version and version_compare.parse_version(version) is not None:
            records.append({
                'input': re.sub(r'^https?://', '', base_url).rstrip('/'),
                'url': base_url,
                'path': path,
                'status': status,
                'version': version,
                'source': 'version_probe',
                'rule': rule.get('id'),
                'confidence': rule.get('confidence'),
                'evidence': evidence[:200],
            })
            # 同一目标命中一条可靠规则即可，避免重复请求
            break
    return records


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='低影响主动版本探测（只读 GET）')
    ap.add_argument('--targets', required=True,
                    help='URL 列表（每行 scheme://host:port）')
    ap.add_argument('--context', required=True, help='context.json（取 product）')
    ap.add_argument('--table', default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'version_probes.json'))
    ap.add_argument('--output', required=True)
    ap.add_argument('--max-targets', type=int, default=50)
    ap.add_argument('--max-requests', type=int, default=2,
                    help='每个目标最多尝试的规则数')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--threads', type=int, default=10)
    ap.add_argument('--verify-tls', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)

    context = load_json(args.context, {}) or {}
    product = str(context.get('product') or '').strip()
    table = load_json(args.table, {}) or {}
    rules = matching_rules(product, table)
    # context 显式指定的版本路径优先（如 WordPress 插件的 readme.txt）
    extra = []
    for p in (context.get('version_probe') or {}).get('paths') or []:
        p = str(p or '').strip()
        if not p:
            continue
        extra.append({
            'id': 'context-path',
            'products': ['*'],
            'path': p,
            'type': 'readme_stable_tag',
            'regex': r'Stable tag:\s*([0-9]+(?:\.[0-9]+){1,3})',
            'confidence': 0.90,
        })
    rules = extra + rules
    for r in rules:
        r['_product'] = product

    try:
        with open(args.targets, encoding='utf-8') as f:
            targets = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(f'[错误] targets 不存在: {args.targets}', file=sys.stderr)
        return 2
    targets = targets[:max(0, args.max_targets)]

    if args.dry_run:
        print(f'product={product!r} targets={len(targets)} rules={[r.get("id") for r in rules]}')
        return 0

    records = []
    if rules and targets:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = [ex.submit(probe_one, t, rules, args.timeout,
                                 args.verify_tls, args.max_requests)
                       for t in targets]
            for fut in as_completed(futures):
                try:
                    records.extend(fut.result())
                except Exception:
                    continue

    d = os.path.dirname(os.path.abspath(args.output))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    print(f'product={product!r}')
    print(f'targets={len(targets)}')
    print(f'requests_rules={len(rules)}')
    print(f'versions_found={len(records)}')
    print(f'output={os.path.abspath(args.output)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

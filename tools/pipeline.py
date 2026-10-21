"""
直连流水线（不依赖 MCP）

背景：项目原先依赖 fofa-mcp / nvd 两个 MCP server；会话重启或网络波动时
MCP 工具可能不可用。本脚本直接用官方 HTTPS API 完成同一套流程：

  NVD API 2.0  -> nvd.json / ranges.json / context.json
  FOFA API     -> stats.json / raw.json
  本地工具      -> probe_inputs -> httpx -> version_probe -> score

用法：
  python tools/pipeline.py --cve CVE-2026-95675 \
      --product "D-Link DAP-1360" \
      --fingerprint 'title="DAP-1360"' \
      [--verify-path /path] [--country CN] [--run-mode auto|candidates|census] \
      [--limit 100] [--export-size 2000] [--version-path /readme.txt]

安全边界：只做被动查询与低影响 GET 探活；不做漏洞利用。
退出码：0 成功；2 输入/API 错误；3 授权范围错误（本脚本不含 scope）。
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import gate
import probe_inputs
import score
import version_compare
import version_probe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'data')
UA = 'cvehound-pipeline/1.0'
FIELDS = 'ip,port,protocol,host,domain,title,server,header,org,country'


def _get_json(url, timeout=30, proxy=None, headers=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {'http': proxy, 'https': proxy}))
    opener = urllib.request.build_opener(*handlers)
    hdrs = {'User-Agent': UA}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs)
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', errors='replace'))


def nvd_fetch(cve_id, timeout=30):
    url = ('https://services.nvd.nist.gov/rest/json/cves/2.0?'
           + urllib.parse.urlencode({'cveId': cve_id}))
    headers = {}
    nvd_key = os.environ.get('NVD_API_KEY', '')
    if nvd_key:
        headers['apiKey'] = nvd_key
    data = None
    for attempt in range(4):
        try:
            data = _get_json(url, timeout=timeout, headers=headers)
            break
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503) and attempt < 3:
                time.sleep(7 * (attempt + 1))
                continue
            raise
    vulns = (data or {}).get('vulnerabilities') or []
    if not vulns:
        return None
    # 统一成项目内 nvd_get_cve 的形状：{"cves": [...]}
    return {'cves': [v.get('cve') or {} for v in vulns]}


def _infer_vuln_type(desc):
    d = str(desc or '').lower()
    table = [
        ('sql injection', 'SQLi'), ('sql', 'SQLi'),
        ('command injection', 'RCE'), ('remote code execution', 'RCE'),
        ('code execution', 'RCE'), ('deserialization', 'RCE'),
        ('path traversal', '路径遍历'), ('directory traversal', '路径遍历'),
        ('arbitrary file read', '任意文件读取'),
        ('file upload', '文件上传'),
        ('xxe', 'XXE'), ('ssrf', 'SSRF'),
        ('unauthorized', '未授权访问'), ('authentication bypass', '未授权访问'),
        ('cross-site scripting', 'XSS'), ('xss', 'XSS'),
        ('information disclosure', '信息泄露'),
    ]
    for needle, label in table:
        if needle in d:
            return label
    return '未知'


def _cve_text(cve):
    for d in cve.get('descriptions') or []:
        if d.get('lang') == 'en':
            return str(d.get('value') or '')
    return ''


def _cwe(cve):
    for w in cve.get('weaknesses') or []:
        ids = w.get('cweIds') or []
        if ids:
            return ids[0]
    return ''


def _references(cve):
    return [r.get('url') for r in cve.get('references') or [] if r.get('url')]


def _product_from_cpe(cve):
    for node in cve.get('configurationNodes') or []:
        for m in node.get('cpeMatch') or []:
            crit = str(m.get('criteria') or '')
            parts = crit.split(':')
            if len(parts) >= 5 and parts[3]:
                return parts[4].replace('_', ' ')
    return ''


def fofa_call(url, timeout=40, proxy=None):
    for attempt in range(4):
        try:
            data = _get_json(url, timeout=timeout, proxy=proxy)
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503) and attempt < 3:
                print(f'[fofa] HTTP {e.code}，60s 后重试', file=sys.stderr)
                time.sleep(60)
                continue
            raise
        if not data.get('error'):
            return data
        code = data.get('errcode') or data.get('error_code')
        msg = data.get('errmsg') or data.get('error')
        print(f'[fofa] error={code} {msg}', file=sys.stderr)
        if str(code) == '45012':
            time.sleep(90)
            continue
        raise RuntimeError(f'FOFA API error: {code} {msg}')
    raise RuntimeError('FOFA API 重试仍失败')


def fofa_stats(query, key, proxy=None):
    qb = base64.b64encode(query.encode('utf-8')).decode('ascii')
    url = ('https://fofa.info/api/v1/search/stats?'
           + urllib.parse.urlencode({'key': key, 'qbase64': qb,
                                     'fields': 'country'}))
    return fofa_call(url, proxy=proxy)


def fofa_search(query, key, size, page=1, proxy=None):
    qb = base64.b64encode(query.encode('utf-8')).decode('ascii')
    url = ('https://fofa.info/api/v1/search/all?'
           + urllib.parse.urlencode({'key': key, 'qbase64': qb,
                                     'fields': FIELDS, 'size': size,
                                     'page': page}))
    return fofa_call(url, proxy=proxy)


def run(cmd, timeout, label):
    started = time.time()
    proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout)
    elapsed = round(time.time() - started, 1)
    out = (proc.stdout or b'').decode('utf-8', errors='replace')
    print(f'[{label}] rc={proc.returncode} {elapsed}s')
    return proc.returncode, out


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='cvehound 直连流水线（无需 MCP）')
    ap.add_argument('--cve', required=True)
    ap.add_argument('--product', default='')
    ap.add_argument('--fingerprint', required=True,
                    help='FOFA 查询，如 title="X" / body="/path/" / cert="X"')
    ap.add_argument('--verify-path', default='')
    ap.add_argument('--country', default='', help='可选；默认全球')
    ap.add_argument('--run-mode', default='auto',
                    choices=('auto', 'candidates', 'census'))
    ap.add_argument('--version-path', action='append', default=[],
                    help='context.version_probe.paths，可多次')
    ap.add_argument('--range', action='append', default=[],
                    help='手工影响区间 START,END[,incl]；可多次，'
                         '用于 NVD configurationNodes 为空的 CVE')
    ap.add_argument('--limit', type=int, default=100)
    ap.add_argument('--export-size', type=int, default=2000)
    ap.add_argument('--max-probe', type=int, default=2000)
    ap.add_argument('--proxy', default=os.environ.get('HTTPS_PROXY', ''))
    ap.add_argument('--skip-nvd', action='store_true',
                    help='复用已有 nvd.json')
    ap.add_argument('--skip-httpx', action='store_true')
    args = ap.parse_args(argv)

    cve = args.cve
    prefix = os.path.join(DATA, cve)
    key = os.environ.get('FOFA_API_KEY', '')
    if not key:
        print('[错误] FOFA_API_KEY 未设置', file=sys.stderr)
        return 2
    os.makedirs(DATA, exist_ok=True)

    # ---- Step 1: NVD ----
    nvd_path = prefix + '_nvd.json'
    if args.skip_nvd and os.path.exists(nvd_path):
        nvd = score.load_required_json(nvd_path, 'nvd')
    else:
        nvd = nvd_fetch(cve)
        if not nvd or not nvd.get('cves'):
            print(f'[错误] NVD 无 {cve} 记录', file=sys.stderr)
            return 2
        with open(nvd_path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(nvd, f, ensure_ascii=False, indent=2)
            f.write('\n')
    cve_obj = nvd['cves'][0]
    product = (args.product or _product_from_cpe(cve_obj)
               or args.fingerprint.strip('"')).strip()
    desc = _cve_text(cve_obj)
    ranges = version_compare.extract_ranges_from_nvd(nvd, product)
    manual_ranges = []
    for spec in args.range:
        parts = [p.strip() for p in str(spec).split(',')]
        start = parts[0] or None
        end = parts[1] if len(parts) > 1 and parts[1] else None
        end_incl = len(parts) > 2 and parts[2].lower() in ('1', 'true', 'incl', 'inclusive')
        manual_ranges.append({
            'start': start, 'start_inclusive': True,
            'end': end, 'end_inclusive': end_incl,
        })
    affected_ranges = (ranges.get('affected_ranges') or []) + manual_ranges
    ctx = {
        'cve_id': cve,
        'product': product,
        'affected_ranges': affected_ranges,
        'warnings': ranges.get('warnings') or [],
        'excluded_versions': [],
        'vuln_type': _infer_vuln_type(desc),
        'cwe': _cwe(cve_obj),
        'references': _references(cve_obj),
        'matched_fingerprint': args.fingerprint,
        'fingerprint_kind': score.fingerprint_kind(args.fingerprint),
        'verify_path': args.verify_path,
        'verify_path_inferred': False,
        'run_mode': args.run_mode,
        'country_mode': ({'type': 'country', 'value': args.country}
                         if args.country else {'type': 'global'}),
        'version_probe': {'enabled': True, 'paths': args.version_path},
        'fofa_query': args.fingerprint,
        'fofa_total': 0,
    }
    with open(prefix + '_context.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(f'[nvd] product={product!r} ranges={len(ctx["affected_ranges"])} '
          f'vuln_type={ctx["vuln_type"]} cwe={ctx["cwe"]}')

    # ---- Step 3: FOFA stats ----
    query = args.fingerprint
    if args.country:
        query += f' && country="{args.country}"'
    stats = fofa_stats(query, key, proxy=args.proxy or None)
    total = int(stats.get('size') or 0)
    print(f'[fofa] size={total}')
    with open(prefix + '_stats.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
        f.write('\n')
    if total == 0:
        print('[错误] FOFA 预检为 0，停止', file=sys.stderr)
        return 2
    ctx['fofa_total'] = total
    with open(prefix + '_context.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2)
        f.write('\n')

    # ---- Step 0.5: gate（决定 ceiling / probe plan）----
    table = version_probe.load_json(
        os.path.join(ROOT, 'tools', 'version_probes.json'), {}) or {}
    g = gate.assess(ctx, stats=stats, cohort_size=total, table=table,
                    max_probe=args.max_probe)
    with open(prefix + '_gate.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(g, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(f'[gate] decision={g["decision"]} ceiling={g["ceiling"]} '
          f'version_observable={g["version_observable"]}')
    if g['decision'] == 'blocked':
        return 2
    if g['decision'] == 'census':
        with open(prefix + '_census.json', 'w', encoding='utf-8', newline='\n') as f:
            json.dump({'cve_id': cve, 'query': query, 'fofa_total': total,
                       'note': '0 条可验证候选；这是资产普查，不是漏洞清单'}, f,
                      ensure_ascii=False, indent=2)
            f.write('\n')
        print('[gate] census：已写 census.json；跳过探活')
        return 0

    # ---- Step 4: FOFA export ----
    size = min(total, args.export_size)
    export = fofa_search(query, key, size, page=1, proxy=args.proxy or None)
    field_names = FIELDS.split(',')
    rows = []
    for arr in export.get('results') or []:
        if not isinstance(arr, list):
            continue
        rows.append({k: (arr[i] if i < len(arr) else '')
                     for i, k in enumerate(field_names)})
    with open(prefix + '_raw.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
        f.write('\n')
    coverage = round(len(rows) / total, 6) if total else 0
    print(f'[fofa] exported={len(rows)} coverage={coverage}')

    # ---- Step 5a: probe inputs ----
    rc, out = run([sys.executable, os.path.join(ROOT, 'tools', 'probe_inputs.py'),
                   '--raw', prefix + '_raw.json', '--prefix', prefix], 120,
                  'probe_inputs')
    if rc != 0:
        print(out)
        return 2
    targets_file = prefix + '_probe_targets.txt'
    urls_file = prefix + '_probe_urls.txt'
    try:
        target_count = sum(1 for _ in open(targets_file, encoding='utf-8'))
    except OSError:
        target_count = 0

    # ---- Step 5b: httpx ----
    httpx_out = prefix + '_httpx.jsonl'
    if not args.skip_httpx:
        threads = 50 if target_count > 300 else 20
        req_timeout = 5 if target_count > 300 else 10
        rc, out = run(['httpx', '-l', targets_file, '-sc', '-title', '-server',
                       '-td', '-cdn', '-j', '-o', httpx_out, '-silent',
                       '-timeout', str(req_timeout), '-threads', str(threads),
                       '-no-color', '-duc', '-auth=false'], 900, 'httpx')
        if rc not in (0, 124) or not os.path.exists(httpx_out):
            print(out[-1000:])
            return 2
    alive = sum(1 for _ in open(httpx_out, encoding='utf-8')) \
        if os.path.exists(httpx_out) else 0
    print(f'[httpx] alive={alive}')

    # ---- Step 5b.5: version probe ----
    probe_out = prefix + '_version_probe.jsonl'
    rc, out = run([sys.executable, os.path.join(ROOT, 'tools', 'version_probe.py'),
                   '--targets', urls_file, '--context', prefix + '_context.json',
                   '--output', probe_out, '--max-targets', '50',
                   '--timeout', '5', '--threads', '10'], 300, 'version_probe')
    versions_found = 0
    if os.path.exists(probe_out):
        versions_found = sum(1 for l in open(probe_out, encoding='utf-8')
                             if l.strip())
    print(f'[version_probe] versions_found={versions_found}')

    # ---- Step 5e: score ----
    rc, out = run([sys.executable, os.path.join(ROOT, 'tools', 'score.py'),
                   '--raw', prefix + '_raw.json',
                   '--httpx', httpx_out,
                   '--cdn', prefix + '_cdn.jsonl',
                   '--waf', prefix + '_waf.json',
                   '--version-probe', probe_out,
                   '--context', prefix + '_context.json',
                   '--output', prefix + '_targets.json',
                   '--limit', str(args.limit),
                   '--selection', 'stratified'], 120, 'score')
    print('\n'.join(out.strip().splitlines()[-12:]))
    if rc != 0:
        return 2
    print(f'[done] targets={prefix}_targets.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())

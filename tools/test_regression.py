"""
cvehound 回归用例

直接运行：python tools/test_regression.py
覆盖曾经出过错或容易出错的地方：
  1. Server 头版本归属（首词锚点误判 —— product="Apache Log4j2" 曾拿到 Apache 的版本）
  2. tech[] 版本归属（产品名与 tech 名的方向性匹配）
  3. org 硬排除关键词匹配（英文词边界 vs 中文子串）
  4. version_compare 三态判定（多段不连续区间、空档、退化闭区间、排除版本）
  5. NVD 影响区间提取（golden 对照）
  6. tech_hit / classify 四档分类（unknown 不许升 likely_affected）
  7. scope 授权范围匹配（精确域名 / 通配 / CIDR / excluded / 空范围拒绝）
  8. probe_inputs 域名优先与裸主机文件（cdncheck 专用）
  9. score.py 子进程退出码（必需输入缺失/损坏 -> 2）
  10. FOFA 标题证据（标题命中产品计入指纹分与标题证据，不叠加）
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import probe_inputs               # noqa: E402
import scope                      # noqa: E402
import score                      # noqa: E402
import version_compare as vc      # noqa: E402

try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

# 从实际发布的词表加载，而不是内联一份副本 ——
# 内联副本会让词表本身的回归测不出来（曾踩过：education 补齐后测试仍通过）
_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'exclude_keywords.json')
with open(_RULES_PATH, encoding='utf-8') as _f:
    RULES = json.load(_f)

FAILS = []


def check(label, got, want):
    ok = got == want
    if not ok:
        FAILS.append(label)
    print(f"  {'OK  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got : {got!r}")
        print(f"        want: {want!r}")


def versions_of(*args):
    """取 collect_versions 产出的版本号列表，方便断言。"""
    return [v['version'] for v in score.collect_versions(*args)]


print("=" * 72)
print("1. Server 头版本归属（白名单）")
print("=" * 72)
check("whitelist: Apache HTTP Server 吃到 Server 头 2.4.39",
      versions_of("Apache HTTP Server", "Apache/2.4.39 (Win64) OpenSSL/1.1.1b", "", [], ""),
      ["2.4.39"])
check("non-whitelist: Apache Log4j2 拿不到 2.4.39（原 bug 场景）",
      versions_of("Apache Log4j2", "Apache/2.4.39 (Win64) OpenSSL/1.1.1b", "", [], ""),
      [])
check("whitelist 命中: Nginx",
      versions_of("Nginx", "nginx/1.20.1", "", [], ""),
      ["1.20.1"])
check("whitelist 命中: Jetty",
      versions_of("Jetty", "Jetty(10.0.25)", "", [], ""),
      ["10.0.25"])
check("whitelist 多词命中: Apache Tomcat",
      versions_of("Apache Tomcat", "", "Apache-Coyote/1.1", [], ""),
      ["1.1"])
check("非白名单 + Server 头无版本: ThinkPHP",
      versions_of("ThinkPHP", "nginx", "nginx", [], ""),
      [])

print()
print("=" * 72)
print("2. tech[] 版本归属")
print("=" * 72)
check("Apache Log4j2 命中 tech 'Log4j:2.14.1'（词首匹配 log4j2←log4j）",
      versions_of("Apache Log4j2", "", "", ["Log4j:2.14.1"], ""),
      ["2.14.1"])
check("PHP 不该命中 tech 'ThinkPHP:5.0.23'",
      versions_of("PHP", "", "", ["ThinkPHP:5.0.23"], ""),
      [])
check("Apache HTTP Server 命中同名 tech",
      versions_of("Apache HTTP Server", "", "", ["Apache HTTP Server:2.4.39"], ""),
      ["2.4.39"])
check("X-Powered-By 分支: PHP",
      versions_of("PHP", "", "", [], "HTTP/1.1 200 OK\nX-Powered-By: PHP/7.4.6\n"),
      ["7.4.6"])
check("X-Powered-By 分支不该串味: Apache Log4j2",
      versions_of("Apache Log4j2", "", "", [], "HTTP/1.1 200 OK\nX-Powered-By: PHP/7.4.6\n"),
      [])

print()
print("=" * 72)
print("3. org 硬排除关键词匹配")
print("=" * 72)
check("正常 ISP 不误伤", score.org_exclusion_hit("Hangzhou Alibaba Advertising Co.,Ltd.", RULES), None)
check("mil 不误伤 Milan", score.org_exclusion_hit("Milan Fashion SRL", RULES), None)
check("mil 不误伤 Emilia", score.org_exclusion_hit("Emilia Romagna Region", RULES), None)
check("mil 不误伤 Milwaukee", score.org_exclusion_hit("Milwaukee Tool Corp", RULES), None)
check("bank 命中", score.org_exclusion_hit("Deutsche Bank AG", RULES), ("finance", "bank"))
check("government 命中（不是 gov 词边界）",
      score.org_exclusion_hit("Beijing Municipal Government", RULES), ("government", "government"))
check("中文 政府 命中", score.org_exclusion_hit("某省人民政府信息中心", RULES), ("government", "政府"))
check("中文 医院 命中", score.org_exclusion_hit("市第一人民医院", RULES), ("medical", "医院"))
check("education 词表补齐后命中",
      score.org_exclusion_hit("Ministry of Education", RULES), ("education", "education"))
check("school 命中",
      score.org_exclusion_hit("Springfield High School District", RULES), ("education", "school"))
check("academy 命中",
      score.org_exclusion_hit("National Academy of Sciences", RULES), ("education", "academy"))
check("university 仍命中",
      score.org_exclusion_hit("Stanford University", RULES), ("education", "university"))

print()
print("=" * 72)
print("4. version_compare 三态判定")
print("=" * 72)
LOG4J = [
    {"start": "2.0.1",  "start_inclusive": True,  "end": "2.3.1",  "end_inclusive": False},
    {"start": "2.4.0",  "start_inclusive": True,  "end": "2.12.2", "end_inclusive": False},
    {"start": "2.13.0", "start_inclusive": True,  "end": "2.15.0", "end_inclusive": False},
]
for v, want in (("2.0.1", "affected"), ("2.3.0", "affected"), ("2.3.1", "unaffected"),
                ("2.4.0", "affected"), ("2.12.1", "affected"), ("2.12.2", "unaffected"),
                ("2.12.5", "unaffected"), ("2.12.9", "unaffected"),
                ("2.13.0", "affected"), ("2.14.9", "affected"), ("2.15.0", "unaffected"),
                ("1.9.0", "unaffected"), ("2.17.0", "unaffected"),
                ("garbage", "unknown"), (None, "unknown")):
    check(f"log4j {str(v):9s} -> {want}", vc.compare(v, LOG4J), want)

check("排除版本命中 -> unaffected", vc.compare("2.14.9", LOG4J, ["2.14.9"]), "unaffected")
check("排除版本变量不存在时仍 affected", vc.compare("2.14.9", LOG4J, []), "affected")
check("无区间 -> unknown", vc.compare("2.4.0", []), "unknown")
check("边界全缺 -> unknown",
      vc.compare("2.4.0", [{"start": None, "end": None}]), "unknown")

EXACT = [{"start": "1.3.0", "start_inclusive": True, "end": "1.3.0", "end_inclusive": True}]
check("退化闭区间 精确版本命中", vc.compare("1.3.0", EXACT), "affected")
check("退化闭区间 邻近版本外", vc.compare("1.4.0", EXACT), "unaffected")
check("退化闭区间 邻近版本内", vc.compare("1.2.9", EXACT), "unaffected")

print()
print("=" * 72)
print("5. NVD 影响区间提取器 extract_ranges_from_nvd")
print("=" * 72)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tests', 'fixtures')


def _fixture(name):
    with open(os.path.join(FIX, name), encoding='utf-8') as f:
        d = json.load(f)
    d.pop('_comment', None)
    return d


ls_nvd = _fixture('log4shell_nvd.json')
ls_want = _fixture('log4shell_ranges.json')
check("log4shell: 提取结果 == golden（含边界/精确版本/多产品过滤/vulnerable=false 排除）",
      vc.extract_ranges_from_nvd(ls_nvd, 'Apache Log4j2'), ls_want)

nc_nvd = _fixture('nonecms_nvd.json')
nc_want = _fixture('nonecms_ranges.json')
check("nonecms: 只有精确版本 -> 退化闭区间 == golden",
      vc.extract_ranges_from_nvd(nc_nvd, 'NoneCms'), nc_want)

_mism = vc.extract_ranges_from_nvd(nc_nvd, 'ThinkPHP')
check("产品不匹配: 仍保留区间（不丢数据）", len(_mism['affected_ranges']), 1)
check("产品不匹配: 产生 warning 提示可能过度匹配", len(_mism['warnings']), 1)

_sel = vc.select_ranges({'product': 'Apache Log4j2',
                         'affected_ranges': ls_want['affected_ranges'],
                         'affected_ranges_by_product': ls_want['affected_ranges_by_product']})
check("提取 -> select_ranges -> compare 端到端: 2.14.9 affected",
      vc.compare('2.14.9', _sel), 'affected')
check("提取 -> select_ranges -> compare 端到端: 2.12.5 空档 unaffected",
      vc.compare('2.12.5', _sel), 'unaffected')
check("提取 -> select_ranges -> compare 端到端: 2.0-beta9 精确版本命中",
      vc.compare('2.0-beta9', _sel), 'affected')
check("提取 -> select_ranges -> compare 端到端: 4.69 不该被 siemens 区间命中",
      vc.compare('4.69', _sel), 'unaffected')

print()
print("=" * 72)
print("6. tech_hit / classify（四档分类）")
print("=" * 72)
check("tech_hit: PHP 不该命中 ThinkPHP", score.tech_hit("PHP", ["ThinkPHP:5.0.23"]), False)
check("tech_hit: ThinkPHP 命中自身", score.tech_hit("ThinkPHP", ["ThinkPHP:5.0.23"]), True)
check("tech_hit: Apache Log4j2 命中 tech Log4j", score.tech_hit("Apache Log4j2", ["Log4j:2.14.1"]), True)
check("tech_hit: Apache HTTP Server 命中同名 tech",
      score.tech_hit("Apache HTTP Server", ["Apache HTTP Server:2.4.39"]), True)

check("classify: 80+affected -> likely_affected",
      score.classify(80, "affected"), "likely_affected")
check("classify: 80+unknown -> probable（unknown 不许升档）",
      score.classify(80, "unknown"), "probable")
check("classify: 60 -> probable", score.classify(60, "unknown"), "probable")
check("classify: 50 -> needs_verification", score.classify(50, "unknown"), "needs_verification")
check("classify: 39 -> rejected", score.classify(39, "affected"), "rejected")

print()
print("=" * 72)
print("7. scope 授权范围（可选 allowlist）")
print("=" * 72)
with tempfile.TemporaryDirectory() as _td:
    _sp = os.path.join(_td, 'scope.json')
    with open(_sp, 'w', encoding='utf-8') as _f:
        json.dump({'domains': ['example.com', '*.test.com'],
                   'cidrs': ['192.0.2.0/24', '2001:db8::/32'],
                   'excluded_hosts': ['skip.example.com', '*.bad.test.com']}, _f)
    sc = scope.load_scope(_sp)

    check("精确域名放行", scope.match_scope('example.com', None, sc)[0], True)
    check("精确域名不含子域", scope.match_scope('a.example.com', None, sc)[0], False)
    check("通配 *.test.com 命中子域", scope.match_scope('a.b.test.com', None, sc)[0], True)
    check("通配 *.test.com 不含根域", scope.match_scope('test.com', None, sc)[0], False)
    check("CIDR 命中（ip 字段）", scope.match_scope('', '192.0.2.10', sc)[0], True)
    check("IPv6 CIDR 命中", scope.match_scope('', '2001:db8::1', sc)[0], True)
    check("CIDR 外不放行", scope.match_scope('', '198.51.100.1', sc)[0], False)
    check("excluded_hosts 优先于放行", scope.match_scope('skip.example.com', None, sc)[0], False)
    check("excluded 通配命中子域", scope.match_scope('x.bad.test.com', None, sc)[0], False)
    check("scheme/端口/大小写归一", scope.match_scope('HTTPS://Example.COM:443/x', None, sc)[0], True)
    check("scope=None 一律放行", scope.match_scope('anything', None, None),
          (True, 'scope 未启用'))

    _rows = [{'host': 'example.com', 'ip': '192.0.2.1'},
             {'host': 'skip.example.com', 'ip': '192.0.2.2'},
             {'host': 'other.org', 'ip': '198.51.100.9'}]
    check("filter_rows 保留/丢弃计数", scope.filter_rows(_rows, sc)[1], 2)

    _bad = os.path.join(_td, 'bad.json')
    with open(_bad, 'w', encoding='utf-8') as _f:
        _f.write('{not json')
    try:
        scope.load_scope(_bad)
        _got = 'no-error'
    except scope.ScopeError:
        _got = 'ScopeError'
    check("损坏 JSON -> ScopeError", _got, 'ScopeError')
    _empty = os.path.join(_td, 'empty.json')
    with open(_empty, 'w', encoding='utf-8') as _f:
        json.dump({}, _f)
    try:
        scope.load_scope(_empty)
        _got = 'no-error'
    except scope.ScopeError:
        _got = 'ScopeError'
    check("空范围 -> ScopeError（禁止空 allowlist 静默放行）", _got, 'ScopeError')

print()
print("=" * 72)
print("8. probe_inputs（域名优先 + cdncheck 裸主机文件）")
print("=" * 72)
check("pick_probe: 有域名用域名，scheme 取 protocol 字段",
      probe_inputs.pick_probe({'ip': '1.2.3.4', 'port': '443',
                               'host': 'example.com', 'protocol': 'http'}),
      ('example.com', '443', 'http'))
check("pick_probe: 裸 IP 回退 ip 字段",
      probe_inputs.pick_probe({'ip': '1.2.3.4', 'port': '443',
                               'host': '1.2.3.4', 'protocol': 'https'}),
      ('1.2.3.4', '443', 'https'))
check("pick_probe: 非法 scheme 按端口回退",
      probe_inputs.pick_probe({'ip': '1.2.3.4', 'port': '8443',
                               'host': '', 'protocol': 'ftp'}),
      ('1.2.3.4', '8443', 'http'))

_prows = [{'ip': '1.2.3.4', 'port': '443', 'host': 'a.com', 'protocol': 'https'},
          {'ip': '1.2.3.4', 'port': '80', 'host': 'a.com', 'protocol': 'http'},
          {'ip': '5.6.7.8', 'port': '8080', 'host': 'b.com', 'protocol': 'http'},
          {'ip': '', 'port': '', 'host': ''}]
_t, _u, _h = probe_inputs.build_probe_lines(_prows)
check("targets 含端口", _t, ['a.com:443', 'a.com:80', 'b.com:8080'])
check("urls 带 scheme", _u, ['https://a.com:443', 'http://a.com:80', 'http://b.com:8080'])
check("hosts 无端口且按主机去重（cdncheck 用）", _h, ['a.com', 'b.com'])

print()
print("=" * 72)
print("9. score.py 子进程：必需输入缺失/损坏的退出码")
print("=" * 72)
_SCORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'score.py')


def _run_score(td, with_raw=True, with_context=True, broken_context=False):
    raw = os.path.join(td, 'raw.json')
    hx = os.path.join(td, 'httpx.jsonl')
    ctx = os.path.join(td, 'ctx.json')
    out = os.path.join(td, 'out.json')
    with open(raw, 'w', encoding='utf-8') as f:
        json.dump([{'ip': '1.2.3.4', 'port': '80', 'host': 'x.com',
                    'protocol': 'http'}], f)
    with open(hx, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'input': 'x.com:80', 'status_code': 200,
                            'title': 't', 'tech': []}) + '\n')
    with open(ctx, 'w', encoding='utf-8') as f:
        f.write('{broken' if broken_context
                else json.dumps({'product': 'X', 'affected_ranges': []}))
    args = [sys.executable, _SCORE,
            '--raw', raw if with_raw else os.path.join(td, 'missing.json'),
            '--httpx', hx,
            '--cdn', os.path.join(td, 'nocdn.jsonl'),
            '--waf', os.path.join(td, 'nowaf.json'),
            '--context', ctx if with_context else os.path.join(td, 'missing2.json'),
            '--output', out]
    return subprocess.run(args, capture_output=True, text=True,
                          encoding='utf-8', errors='replace').returncode


with tempfile.TemporaryDirectory() as _td2:
    check("cdn/waf 缺失不阻塞 -> 0", _run_score(_td2), 0)
    check("raw 缺失 -> 2", _run_score(_td2, with_raw=False), 2)
    check("context 缺失 -> 2", _run_score(_td2, with_context=False), 2)
    check("context 损坏 -> 2", _run_score(_td2, broken_context=True), 2)

print()
print("=" * 72)
print("10. FOFA 标题证据（框架类 CVE 指纹盲区通道）")
print("=" * 72)
check("fofa_title_hit: 标题含产品名",
      score.fofa_title_hit("ThinkAdmin", "", "系统登录 · ThinkAdmin"), True)
check("fofa_title_hit: 大小写不敏感",
      score.fofa_title_hit("ThinkAdmin", "", "系统登录 · thinkadmin"), True)
check("fofa_title_hit: fingerprint 回退（多词产品只写短名）",
      score.fofa_title_hit("Apache Log4j2", "Log4j2", "登录 - Log4j2 控制台"), True)
check("fofa_title_hit: 标题不含产品不命中",
      score.fofa_title_hit("ThinkAdmin", "ThinkAdmin", "系统登录 · 某某系统"), False)
check("fofa_title_hit: 空标题不命中",
      score.fofa_title_hit("ThinkAdmin", "ThinkAdmin", ""), False)
check("fofa_title_hit: 空产品且空指纹不命中",
      score.fofa_title_hit("", "", "随便什么标题"), False)


def _run_score_full(td, fofa_title, httpx_title=''):
    """完整跑一次 score.py，返回解析后的 targets.json 列表。"""
    raw = os.path.join(td, 'raw.json')
    hx = os.path.join(td, 'httpx.jsonl')
    ctx = os.path.join(td, 'ctx.json')
    out = os.path.join(td, 'out.json')
    with open(raw, 'w', encoding='utf-8') as f:
        json.dump([{'ip': '1.2.3.4', 'port': '80', 'host': 'x.com',
                    'protocol': 'http', 'title': fofa_title}], f)
    with open(hx, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'input': 'x.com:80', 'status_code': 302,
                            'title': httpx_title, 'tech': [],
                            'location': '/admin/login.html'}) + '\n')
    with open(ctx, 'w', encoding='utf-8') as f:
        json.dump({'product': 'ThinkAdmin', 'matched_fingerprint': 'ThinkAdmin',
                   'affected_ranges': [{'start': '6.0', 'start_inclusive': True,
                                        'end': '6.0', 'end_inclusive': True}]}, f)
    subprocess.run([sys.executable, _SCORE,
                    '--raw', raw, '--httpx', hx,
                    '--cdn', os.path.join(td, 'nocdn.jsonl'),
                    '--waf', os.path.join(td, 'nowaf.json'),
                    '--context', ctx, '--output', out],
                   capture_output=True, text=True,
                   encoding='utf-8', errors='replace')
    with open(out, encoding='utf-8') as f:
        return json.load(f)


with tempfile.TemporaryDirectory() as _td3:
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin')
    check("E2E: FOFA 标题命中 + httpx 空标题 -> 1 条输出", len(_rows), 1)
    check("E2E: match_score=50",
          _rows[0]['match_score'] if _rows else None, 50)
    check("E2E: classification=needs_verification",
          _rows[0]['classification'] if _rows else None, 'needs_verification')
    check("E2E: version_status=unknown",
          _rows[0]['version_status'] if _rows else None, 'unknown')
    _rows = _run_score_full(_td3, '系统登录 · 某某系统')
    check("E2E: 标题不含产品 -> 空输出（保守不放水）", len(_rows), 0)
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin',
                            httpx_title='系统登录 · ThinkAdmin')
    check("E2E: httpx 标题也在时标题证据不叠加（仍 50）",
          _rows[0]['match_score'] if _rows else None, 50)

print()
print("=" * 72)
if FAILS:
    print(f"*** {len(FAILS)} 个用例失败 ***")
    for f in FAILS:
        print("   -", f)
    sys.exit(1)
print("全部通过")

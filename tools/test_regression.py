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

import alive_filter               # noqa: E402
import census                     # noqa: E402
import fofa_cache                 # noqa: E402
import gate                       # noqa: E402
import probe_inputs               # noqa: E402
import run_state                  # noqa: E402
import scope                      # noqa: E402
import score                      # noqa: E402
import version_compare as vc      # noqa: E402
import version_probe              # noqa: E402
import waf_batch                  # noqa: E402

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


def _run_score_full(td, fofa_title, httpx_title='', tech=None,
                    fingerprint='ThinkAdmin', version=None,
                    cdn_missing=True, waf_missing=True):
    """完整跑一次 score.py，返回解析后的 targets.json 列表。"""
    raw = os.path.join(td, 'raw.json')
    hx = os.path.join(td, 'httpx.jsonl')
    ctx = os.path.join(td, 'ctx.json')
    out = os.path.join(td, 'out.json')
    with open(raw, 'w', encoding='utf-8') as f:
        json.dump([{'ip': '1.2.3.4', 'port': '80', 'host': 'x.com',
                    'protocol': 'http', 'title': fofa_title,
                    'country': 'CN'}], f)
    with open(hx, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'input': 'x.com:80', 'status_code': 302,
                            'title': httpx_title, 'tech': tech or [],
                            'location': '/admin/login.html'}) + '\n')
    ranges = []
    if version:
        ranges = [{'start': version, 'start_inclusive': True,
                   'end': version, 'end_inclusive': True}]
    with open(ctx, 'w', encoding='utf-8') as f:
        json.dump({'product': 'ThinkAdmin', 'matched_fingerprint': fingerprint,
                   'affected_ranges': ranges}, f)
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
    # title= 查询自证：标题命中和标题非空都不再计分 -> 低于门槛被剔除
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin',
                            fingerprint='title="ThinkAdmin"')
    check("E2E: title= 查询自证 -> 0 条输出", len(_rows), 0)

    # 独立强证据 tech 命中 -> 40 分，进入 needs_verification
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin',
                            fingerprint='title="ThinkAdmin"',
                            tech=['ThinkAdmin'])
    check("E2E: tech 命中 -> 1 条输出", len(_rows), 1)
    check("E2E: tech 命中 -> match_score=40",
          _rows[0]['match_score'] if _rows else None, 40)
    check("E2E: tech 命中 -> needs_verification",
          _rows[0]['classification'] if _rows else None, 'needs_verification')
    check("E2E: tech 命中 -> tier B",
          _rows[0]['confidence_tier'] if _rows else None, 'B')
    check("E2E: version_status=unknown",
          _rows[0]['version_status'] if _rows else None, 'unknown')
    check("E2E: 缺失 waf/cdn -> reachability=not_tested",
          _rows[0]['reachability'] if _rows else None, 'not_tested')
    check("E2E: 缺失 waf/cdn -> verification_cost=None",
          _rows[0]['verification_cost'] if _rows else None, None)

    # tech + live title（title= 查询下 live 标题仍算弱证据）
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin',
                            fingerprint='title="ThinkAdmin"',
                            tech=['ThinkAdmin'], httpx_title='ThinkAdmin')
    check("E2E: tech + live title -> 50",
          _rows[0]['match_score'] if _rows else None, 50)

    # tech + 版本命中 -> 100（clamp）+ tier A
    _rows = _run_score_full(_td3, '系统登录 · ThinkAdmin',
                            fingerprint='title="ThinkAdmin"',
                            tech=['ThinkAdmin:6.0'], version='6.0')
    check("E2E: tech + affected -> match_score=90",
          _rows[0]['match_score'] if _rows else None, 90)
    check("E2E: tech + affected -> likely_affected",
          _rows[0]['classification'] if _rows else None, 'likely_affected')
    check("E2E: tech + affected -> tier A",
          _rows[0]['confidence_tier'] if _rows else None, 'A')

# ======================================================================
# 11. alive_filter：用 httpx 结果过滤 wafw00f 输入
# ======================================================================
print()
print("=" * 72)
print("11. alive_filter（wafw00f 输入过滤）")
print("=" * 72)

with tempfile.TemporaryDirectory() as _td4:
    _hx = os.path.join(_td4, 'httpx.jsonl')
    _urls = os.path.join(_td4, 'urls.txt')
    _out = os.path.join(_td4, 'waf_input.txt')
    with open(_hx, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'input': '1.2.3.4:80'}) + '\n')
        f.write(json.dumps({'input': '5.6.7.8:443', 'failed': False}) + '\n')
        f.write(json.dumps({'input': '9.9.9.9:8080', 'failed': True}) + '\n')
        f.write('这一行不是 json\n')
    with open(_urls, 'w', encoding='utf-8', newline='\n') as f:
        f.write('http://1.2.3.4:80\n')       # 存活 -> 保留
        f.write('https://9.9.9.9:8080\n')    # httpx 判死 -> 剔除
        f.write('https://5.6.7.8:443\n')     # 存活 -> 保留
        f.write('http://10.0.0.1:80\n')      # 不在 httpx 结果里 -> 剔除

    check("alive_filter: 退出码 0",
          alive_filter.main(['--httpx', _hx, '--urls', _urls, '--output', _out]), 0)
    with open(_out, encoding='utf-8') as f:
        _kept = [ln.strip() for ln in f if ln.strip()]
    check("alive_filter: 只留存活且保序（坏行忽略、failed 剔除）",
          _kept, ['http://1.2.3.4:80', 'https://5.6.7.8:443'])
    check("alive_filter: httpx 文件缺失 -> 退出码 2",
          alive_filter.main(['--httpx', os.path.join(_td4, 'nope.jsonl'),
                             '--urls', _urls, '--output', _out]), 2)
    check("alive_filter: URL 列表缺失 -> 退出码 2",
          alive_filter.main(['--httpx', _hx,
                             '--urls', os.path.join(_td4, 'nope.txt'),
                             '--output', _out]), 2)

# ======================================================================
# 12. build_hint：verify_path 在三档 hint 里都要出现
# ======================================================================
print()
print("=" * 72)
print("12. build_hint（verify_path 追加）")
print("=" * 72)

_VP = '/index/Search/index.html?keyword='
_h_affected_waf = score.build_hint(True, 'affected', _VP)
_h_affected = score.build_hint(False, 'affected', _VP)
_h_unknown_waf = score.build_hint(True, 'unknown', _VP)
_h_unknown = score.build_hint(False, 'unknown', _VP)

check("hint affected+waf 含验证路径", _VP in _h_affected_waf, True)
check("hint affected 含验证路径", _VP in _h_affected, True)
# 这条是本次修复的回归点：unknown 分支此前会丢掉 verify_path
check("hint unknown+waf 含验证路径", _VP in _h_unknown_waf, True)
check("hint unknown 含验证路径", _VP in _h_unknown, True)
check("hint unknown 无 verify_path 时不出现后缀",
      '建议验证路径' in score.build_hint(False, 'unknown', ''), False)
check("hint unknown 基线措辞不变",
      score.build_hint(False, 'unknown', ''), '需手动确认指纹后再核验')

# verify_path_inferred：推断路径必须带「（推测，需确认）」标记
check("hint 推断路径带推测标记",
      '（推测，需确认）' in score.build_hint(False, 'unknown', _VP, True), True)
check("hint 实证路径不带推测标记",
      '（推测，需确认）' in _h_unknown, False)
check("hint 空 verify_path 即使 inferred=True 也无后缀",
      '建议验证路径' in score.build_hint(False, 'unknown', '', True), False)

# 端到端：context.json 的 verify_path_inferred 要一路传到 hint
with tempfile.TemporaryDirectory() as _td5:
    _r5 = os.path.join(_td5, 'raw.json')
    _x5 = os.path.join(_td5, 'httpx.jsonl')
    _c5 = os.path.join(_td5, 'ctx.json')
    _o5 = os.path.join(_td5, 'out.json')
    with open(_r5, 'w', encoding='utf-8') as f:
        json.dump([{'ip': '1.2.3.4', 'port': '80', 'host': 'x.com',
                    'protocol': 'http', 'title': 'ThinkAdmin'}], f)
    with open(_x5, 'w', encoding='utf-8') as f:
        f.write(json.dumps({'input': 'x.com:80', 'status_code': 200,
                            'title': 'ThinkAdmin',
                            'tech': ['ThinkAdmin']}) + '\n')
    with open(_c5, 'w', encoding='utf-8') as f:
        json.dump({'product': 'ThinkAdmin', 'matched_fingerprint': 'ThinkAdmin',
                   'affected_ranges': [], 'verify_path': '/admin/x?a=',
                   'verify_path_inferred': True}, f)
    subprocess.run([sys.executable, _SCORE, '--raw', _r5, '--httpx', _x5,
                    '--cdn', os.path.join(_td5, 'nocdn.jsonl'),
                    '--waf', os.path.join(_td5, 'nowaf.json'),
                    '--context', _c5, '--output', _o5],
                   capture_output=True, text=True,
                   encoding='utf-8', errors='replace')
    with open(_o5, encoding='utf-8') as f:
        _rows5 = json.load(f)
    check("E2E: context.verify_path_inferred 传到 hint（带推测标记）",
          '（推测，需确认）' in (_rows5[0]['verify_hint'] if _rows5 else ''),
          True)

# ======================================================================
# 13. 证据独立性 / tier / 分层选择 / 证据包
# ======================================================================
print()
print("=" * 72)
print("13. 证据独立性与交付分级")
print("=" * 72)

check("fingerprint_kind: title 查询",
      score.fingerprint_kind('title="Kofax"'), 'title')
check("fingerprint_kind: app 查询",
      score.fingerprint_kind('app="VeraSMART"'), 'app')
check("fingerprint_kind: 无等号视为 unknown",
      score.fingerprint_kind('VeraSMART'), 'unknown')
check("title 查询的 FOFA 标题命中不算独立",
      score.fofa_title_is_independent('title="Kofax"'), False)
check("app 查询的 FOFA 标题命中算独立",
      score.fofa_title_is_independent('app="VeraSMART"'), True)

_FP_RULES = score.load_json(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'fingerprint_rules.json'), {})
check("negative_hits: blog -> hard",
      score.negative_hits('My Blog', _FP_RULES)[0]['severity'], 'hard')
check("negative_hits: news -> soft",
      score.negative_hits('Latest News', _FP_RULES)[0]['severity'], 'soft')
check("negative_hits: 中文博彩 -> gray",
      score.negative_hits('澳门博彩', _FP_RULES)[0]['severity'], 'gray')
check("negative_hits: 正常标题不命中",
      score.negative_hits('Tautulli Dashboard', _FP_RULES), [])

_raw_neg = [{'ip': '1.2.3.4', 'port': '80', 'host': 'x.com',
             'protocol': 'http', 'title': 'Tautulli Blog'}]
_hx_neg = [{'input': 'x.com:80', 'status_code': 200,
            'title': 'Tautulli Blog', 'tech': ['Tautulli']}]
_ctx_neg = {'product': 'Tautulli', 'matched_fingerprint': 'app="Tautulli"',
            'affected_ranges': []}
_kept_neg, _ = score.evaluate_rows(
    _raw_neg, _hx_neg, [], [], _ctx_neg, {}, {}, min_score=0, limit=10,
    fingerprint_rules=_FP_RULES)
check("negative: hard 词把 tier 封顶为 C",
      _kept_neg[0]['confidence_tier'], 'C')
check("negative: hard 词扣 15 分", _kept_neg[0]['score_penalty'], -15)

check("tier: affected -> A",
      score.classify_tier('affected', False), 'A')
check("tier: 强证据 + unknown -> B",
      score.classify_tier('unknown', True), 'B')
check("tier: 弱证据 -> C",
      score.classify_tier('unknown', False), 'C')

check("server_product_hit: server 点名产品",
      score.server_product_hit('Nginx', 'nginx/1.18.0', '', ''), True)
check("server_product_hit: 无关 server 不命中",
      score.server_product_hit('Tautulli', 'nginx/1.18.0', '', ''), False)
check("server_product_hit: X-Powered-By 点名产品",
      score.server_product_hit('ThinkPHP', '', '',
                               'X-Powered-By: ThinkPHP/6.0'), True)

_pv = score.probe_versions_for(
    [{'input': 'x.com:80', 'version': '2.10.0', 'source': 'version_probe'}],
    'Tautulli')
check("probe_versions_for: 解析版本", _pv[0]['version'], '2.10.0')
check("probe_versions_for: 来源为 version_probe", _pv[0]['source'], 'version_probe')

_ev = score.build_evidence(
    {'title': 'T', 'server': 'S', 'org': 'O', 'country': 'US'},
    {'status_code': 200, 'title': 'T', 'webserver': 'S',
     'tech': ['Tautulli:2.10.0'], 'url': 'http://x:80'},
    _pv, 'affected', True, False, True, ['Cloudflare'])
check("evidence: 含 fofa/httpx/version/reachability",
      sorted(_ev.keys()), ['fofa', 'httpx', 'reachability', 'version'])
check("evidence: 不含原始 body/header",
      'body' in _ev['httpx'] or 'header' in _ev['httpx'], False)
check("evidence: reachability tested=True", _ev['reachability']['tested'], True)

_vc = score.build_verify_commands(
    'https://x:443', '/api/upload', 'Tautulli',
    [{'start': '2.0', 'start_inclusive': True, 'end': '2.17.0',
      'end_inclusive': False}])
check("verify_commands: 生成路径与版本两条",
      [c['label'] for c in _vc], ['建议验证路径', '版本判定'])
check("verify_commands: 路径拼接正确",
      _vc[0]['url'], 'https://x:443/api/upload')

# 分层选择：同分下按国家轮转 + 可复现
_fake = []
for i, c in enumerate(['CN'] * 30 + ['US'] * 10 + ['DE'] * 5):
    _fake.append({'ip': f'10.0.0.{i}', 'port': 80, 'url': f'http://10.0.0.{i}',
                  'match_score': 50, 'confidence_tier': 'B',
                  'verification_cost': None, 'country': c})
_pick1, _, _tr, _reason = score.select_targets(_fake, 40, 20, 'stratified')
_pick2, _, _, _ = score.select_targets(list(reversed(_fake)), 40, 20, 'stratified')
check("select_targets: stratified 截断标记", _tr, True)
check("select_targets: 结果可复现",
      sorted((x['ip'] for x in _pick1)), sorted((x['ip'] for x in _pick2)))
check("select_targets: 每个国家都被抽到",
      len({x['country'] for x in _pick1}), 3)

# ======================================================================
# 14. 主动版本探测与可验证性闸门（纯离线）
# ======================================================================
print()
print("=" * 72)
print("14. version_probe / gate（纯离线）")
print("=" * 72)

_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'version_probes.json')
_table = version_probe.load_json(_TABLE_PATH, {}) or {}

_rule = next(r for r in _table['rules'] if r['id'] == 'tautulli-get-version')
_v, _ = version_probe.extract_version(
    _rule, 200, {}, '{"response":{"data":{"version":"2.10.0"}}}', 'Tautulli')
check("version_probe: JSON 路径提取", _v, '2.10.0')

_rule = next(r for r in _table['rules'] if r['id'] == 'generic-server-header')
_v, _ = version_probe.extract_version(
    _rule, 200, {'Server': 'nginx/1.18.0'}, '', 'Nginx')
check("version_probe: Server 头提取", _v, '1.18.0')
_v, _ = version_probe.extract_version(
    _rule, 200, {'Server': 'nginx/1.18.0'}, '', 'Tautulli')
check("version_probe: 产品不匹配不采信", _v, None)

_rule = next(r for r in _table['rules'] if r['id'] == 'wordpress-generator')
_v, _ = version_probe.extract_version(
    _rule, 200, {},
    '<meta name="generator" content="WordPress 6.4.2">', 'WordPress')
check("version_probe: generator meta 提取", _v, '6.4.2')

check("version_probe: Tautulli 命中专用规则",
      any(r['id'] == 'tautulli-get-version'
          for r in version_probe.matching_rules('Tautulli', _table)), True)

_g = gate.assess({'product': 'Tautulli', 'affected_ranges': []},
                 table=_table)
check("gate: 有专用版本端点的产品 -> candidates", _g['decision'], 'candidates')
check("gate: candidates 启用 version_probe",
      _g['probe_plan']['version_probe']['enabled'], True)

_g = gate.assess({'product': 'SomeUnknownProduct', 'affected_ranges': []},
                 table=_table)
check("gate: 版本不可观测 -> census", _g['decision'], 'census')
check("gate: census 关闭 waf", _g['probe_plan']['waf']['enabled'], False)

_g = gate.assess({'product': '', 'affected_ranges': []}, table=_table)
check("gate: 无产品 -> blocked", _g['decision'], 'blocked')

_g = gate.assess({'product': 'Tautulli', 'affected_ranges': [],
                  'version_observable': True}, cohort_size=5000, table=_table)
check("gate: 大候选池 -> sampled", _g['decision'], 'sampled')

# ======================================================================
# 15. run_state / waf_batch / probe_inputs sampling（纯离线）
# ======================================================================
print()
print("=" * 72)
print("15. run_state / waf_batch / sampling")
print("=" * 72)

import shutil  # noqa: E402

_td6 = tempfile.mkdtemp()
try:
    _man = os.path.join(_td6, 'run.json')
    _art = os.path.join(_td6, 'nvd.json')
    with open(_art, 'w', encoding='utf-8') as f:
        f.write('{}')
    check("run_state: init",
          run_state.main(['init', '--manifest', _man, '--cve', 'CVE-X',
                          '--query', 'q']), 0)
    check("run_state: mark",
          run_state.main(['mark', '--manifest', _man, '--stage', 'nvd',
                          '--status', 'done', '--artifact', _art]), 0)
    check("run_state: validate 可复用",
          run_state.main(['validate', '--manifest', _man, '--stage', 'nvd',
                          '--artifact', _art]), 0)
    with open(_art, 'w', encoding='utf-8') as f:
        f.write('{"changed":true}')
    check("run_state: hash 变化 -> 需重跑",
          run_state.main(['validate', '--manifest', _man, '--stage', 'nvd',
                          '--artifact', _art]), 1)
    check("run_state: 未标记阶段 -> 需重跑",
          run_state.main(['validate', '--manifest', _man, '--stage', 'waf',
                          '--artifact', _art]), 1)
finally:
    shutil.rmtree(_td6, ignore_errors=True)

check("waf_batch: 分批形状",
      [len(b) for b in waf_batch.plan_batches(list(range(70)), 32)],
      [32, 32, 6])
check("waf_batch: 空输入", waf_batch.plan_batches([], 32), [])

_sample_rows = [
    {'host': f'h{i}.com', 'port': '80', 'ip': f'1.1.1.{i}', 'country': c}
    for i, c in enumerate(['CN'] * 30 + ['US'] * 10 + ['DE'] * 5)]
_sampled = probe_inputs._sample_rows(_sample_rows, 20, 'country')
check("probe_inputs sampling: 数量", len(_sampled), 20)
check("probe_inputs sampling: 国家覆盖",
      len({r['country'] for r in _sampled}), 3)

# fofa_cache：miss -> put -> hit
_td7 = tempfile.mkdtemp()
try:
    _cd = os.path.join(_td7, 'cache')
    _src = os.path.join(_td7, 'src.json')
    _out = os.path.join(_td7, 'out.json')
    with open(_src, 'w', encoding='utf-8') as f:
        f.write('{"results":[]}')
    _common = ['--query', 'q', '--page', '1', '--size', '2000',
               '--fields', 'ip', '--cache-dir', _cd]
    check("fofa_cache: 未命中 -> 10",
          fofa_cache.main(['get'] + _common + ['--out', _out]), 10)
    check("fofa_cache: put -> 0",
          fofa_cache.main(['put'] + _common + ['--file', _src]), 0)
    check("fofa_cache: 命中 -> 0",
          fofa_cache.main(['get'] + _common + ['--out', _out]), 0)
    check("fofa_cache: 命中文件存在", os.path.exists(_out), True)
finally:
    shutil.rmtree(_td7, ignore_errors=True)

# census：资产普查产物
_td8 = tempfile.mkdtemp()
try:
    _cr = os.path.join(_td8, 'raw.json')
    _cc = os.path.join(_td8, 'ctx.json')
    _cs = os.path.join(_td8, 'stats.json')
    _co = os.path.join(_td8, 'census.json')
    with open(_cr, 'w', encoding='utf-8') as f:
        json.dump([
            {'ip': '1.1.1.1', 'port': '80', 'host': 'a.com',
             'title': 'T', 'country': 'US', 'org': 'O'},
            {'ip': '2.2.2.2', 'port': '443', 'host': 'b.com',
             'title': 'T', 'country': 'CN', 'org': 'O'},
        ], f)
    with open(_cc, 'w', encoding='utf-8') as f:
        json.dump({'cve_id': 'CVE-X', 'product': 'P', 'fofa_query': 'q'}, f)
    with open(_cs, 'w', encoding='utf-8') as f:
        json.dump({'size': 100}, f)
    check("census: 退出码 0",
          census.main(['--raw', _cr, '--context', _cc,
                       '--stats', _cs, '--output', _co]), 0)
    _cdoc = json.load(open(_co, encoding='utf-8'))
    check("census: exported", _cdoc['exported'], 2)
    check("census: coverage_ratio", _cdoc['coverage_ratio'], 0.02)
    check("census: country", _cdoc['country'], {'US': 1, 'CN': 1})
    check("census: 明确非漏洞清单",
          '不是漏洞清单' in _cdoc['note'], True)
finally:
    shutil.rmtree(_td8, ignore_errors=True)

print()
print("=" * 72)
if FAILS:
    print(f"*** {len(FAILS)} 个用例失败 ***")
    for f in FAILS:
        print("   -", f)
    sys.exit(1)
print("全部通过")

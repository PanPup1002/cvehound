"""
授权范围（allowlist）控制 —— 可选功能。

**scope 未提供时一律放行**，本模块不改变默认行为；只有在用户显式提供
scope 文件时才启用强制过滤（探活前过滤 + 评分时再次过滤，双重保险）。

scope 文件（JSON，与项目其余配置格式保持一致，不引入 YAML 依赖）：

{
  "domains": ["example.com", "*.example.com"],
  "cidrs": ["192.0.2.0/24"],
  "excluded_hosts": ["skip.example.com"]
}

匹配规则：
  - domains 里不带通配的条目 = 精确匹配该域名（大小写归一）
  - "*.example.com" = 匹配任意层级子域（a.example.com / a.b.example.com），
    不含 example.com 本身 —— 需要根域时两条都写（与改进方案 §12 示例一致）
  - cidrs 用标准库 ipaddress 判断，ip 命中任一网段即放行
  - excluded_hosts 优先于放行规则，命中即排除

加载失败（文件缺失 / JSON 损坏 / 顶层不是对象 / 规则为空）抛 ScopeError，
由调用方决定退出码（score.py / probe_inputs.py 用 3）。
"""

import ipaddress
import json
import os


class ScopeError(ValueError):
    pass


def load_scope(path):
    if not path:
        return None
    if not os.path.exists(path):
        raise ScopeError(f'授权范围文件不存在: {path}')
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ScopeError(f'授权范围文件 JSON 损坏: {e}')
    if not isinstance(data, dict):
        raise ScopeError('授权范围文件顶层必须是 JSON 对象')
    domains = data.get('domains') or []
    cidrs = data.get('cidrs') or []
    excluded = data.get('excluded_hosts') or []
    if not isinstance(domains, list) or not isinstance(cidrs, list) \
            or not isinstance(excluded, list):
        raise ScopeError('domains / cidrs / excluded_hosts 必须是数组')
    if not (domains or cidrs):
        raise ScopeError('授权范围为空：domains 与 cidrs 至少要有一个')
    return {
        'domains': [str(d).strip().lower() for d in domains if str(d).strip()],
        'cidrs': [str(c).strip() for c in cidrs if str(c).strip()],
        'excluded_hosts': [str(h).strip().lower() for h in excluded if str(h).strip()],
    }


def norm_host(value):
    """归一为小写裸主机名：去 scheme / 端口 / 路径 / 尾部点。"""
    s = str(value or '').strip().lower()
    if not s:
        return ''
    if '://' in s:
        s = s.split('://', 1)[1]
    s = s.split('/')[0].split('?')[0]
    if s.startswith('['):                       # [::1]:80 形态
        return s.split(']')[0].lstrip('[').rstrip('.')
    if ':' in s:
        s = s.split(':', 1)[0]
    return s.rstrip('.')


def _domain_match(host, pattern):
    if pattern.startswith('*.'):
        return host.endswith('.' + pattern[2:])
    return host == pattern


def match_scope(host, ip, scope):
    """返回 (allowed, reason)。scope 为 None/空时一律 (True, 'scope 未启用')。"""
    if not scope:
        return True, 'scope 未启用'
    h = norm_host(host)
    for ex in scope['excluded_hosts']:
        if h and _domain_match(h, ex):
            return False, f'excluded_hosts: {ex}'
    # ip 字段与 host 字段里可能是 IP 字面量，两者都试 CIDR
    for cand in (str(ip or '').strip(), h):
        if not cand:
            continue
        try:
            addr = ipaddress.ip_address(cand)
        except ValueError:
            continue
        for c in scope['cidrs']:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                raise ScopeError(f'cidr 不合法: {c}')
            if addr in net:
                return True, f'cidr: {c}'
    if h:
        for d in scope['domains']:
            if _domain_match(h, d):
                return True, f'domain: {d}'
    return False, '不在授权范围'


def filter_rows(rows, scope):
    """按 scope 过滤 raw 行，返回 (kept, dropped)。scope 为空时原样返回。"""
    if not scope:
        return list(rows), 0
    kept, dropped = [], 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = row.get('host') or row.get('domain') or ''
        if match_scope(host, row.get('ip'), scope)[0]:
            kept.append(row)
        else:
            dropped += 1
    return kept, dropped

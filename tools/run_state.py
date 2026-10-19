"""
运行清单 / 断点续跑（最小实现）

每个 CVE 一个 {CVE}_run.json，记录：
  - 查询、context 哈希、配置；
  - 每个 stage 的状态与时间；
  - 关键产物的路径、大小、sha256；
  - 计数（raw/exported/alive/final）。

用途：会话中断后 `status` 查看进度，`validate` 判断某阶段产物是否可复用，
避免重复调用 FOFA 或重复探活。

用法：
  python tools/run_state.py init --manifest data/CVE_x_run.json --cve CVE-x --query '...'
  python tools/run_state.py mark --manifest ... --stage nvd --status done --artifact data/CVE_x_nvd.json
  python tools/run_state.py mark --manifest ... --stage fofa_export --status done --counts '{"exported":2000}'
  python tools/run_state.py status --manifest ...
  python tools/run_state.py validate --manifest ... --stage nvd --artifact data/CVE_x_nvd.json
    # 退出码 0 = 可复用；1 = 需要重跑

仅使用标准库；写盘采用临时文件 + os.replace，避免半截 JSON。
"""

import argparse
import hashlib
import json
import os
import sys
import time


def _now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def load(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def save(path, data):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')
    os.replace(tmp, path)


def cmd_init(args):
    data = {
        'schema_version': 1,
        'cve_id': args.cve,
        'created_at': _now(),
        'updated_at': _now(),
        'query': args.query or '',
        'context_sha256': _sha256(args.context) if args.context else None,
        'scope_sha256': _sha256(args.scope) if args.scope else None,
        'config': json.loads(args.config) if args.config else {},
        'stages': {},
        'artifacts': {},
        'counts': {},
    }
    save(args.manifest, data)
    print(f"manifest={os.path.abspath(args.manifest)}")
    return 0


def cmd_mark(args):
    data = load(args.manifest) or {}
    data.setdefault('stages', {})
    data.setdefault('artifacts', {})
    data.setdefault('counts', {})
    data['stages'][args.stage] = {
        'status': args.status,
        'at': _now(),
    }
    for art in args.artifact or []:
        data['artifacts'][art] = {
            'path': art,
            'sha256': _sha256(art),
            'size': os.path.getsize(art) if os.path.exists(art) else None,
            'recorded_at': _now(),
        }
    if args.counts:
        try:
            data['counts'].update(json.loads(args.counts))
        except json.JSONDecodeError:
            print('[warn] --counts 不是合法 JSON，已忽略', file=sys.stderr)
    data['updated_at'] = _now()
    save(args.manifest, data)
    print(f"stage={args.stage} status={args.status}")
    return 0


def cmd_status(args):
    data = load(args.manifest)
    if data is None:
        print(f'[错误] manifest 不存在或损坏: {args.manifest}', file=sys.stderr)
        return 2
    print(f"cve_id={data.get('cve_id')}")
    print(f"query={data.get('query')}")
    print(f"updated_at={data.get('updated_at')}")
    for name, st in sorted((data.get('stages') or {}).items()):
        print(f"stage {name}: {st.get('status')} at {st.get('at')}")
    for name, art in sorted((data.get('artifacts') or {}).items()):
        exists = os.path.exists(art.get('path') or '')
        print(f"artifact {name}: exists={exists} size={art.get('size')}")
    for k, v in sorted((data.get('counts') or {}).items()):
        print(f"count {k}={v}")
    return 0


def cmd_validate(args):
    data = load(args.manifest)
    if data is None:
        print('reusable=0 reason=manifest_missing')
        return 1
    stage = (data.get('stages') or {}).get(args.stage) or {}
    if stage.get('status') != 'done':
        print(f"reusable=0 reason=stage_not_done status={stage.get('status')}")
        return 1
    art = (data.get('artifacts') or {}).get(args.artifact)
    if not art:
        print('reusable=0 reason=artifact_not_recorded')
        return 1
    if not os.path.exists(args.artifact):
        print('reusable=0 reason=artifact_missing')
        return 1
    actual = _sha256(args.artifact)
    if art.get('sha256') and actual != art['sha256']:
        print('reusable=0 reason=hash_mismatch')
        return 1
    print('reusable=1')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='运行清单 / 断点续跑')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('init')
    p.add_argument('--manifest', required=True)
    p.add_argument('--cve', required=True)
    p.add_argument('--query', default='')
    p.add_argument('--context', default=None)
    p.add_argument('--scope', default=None)
    p.add_argument('--config', default=None, help='JSON 字符串')
    p.set_defaults(func=cmd_init)

    p = sub.add_parser('mark')
    p.add_argument('--manifest', required=True)
    p.add_argument('--stage', required=True)
    p.add_argument('--status', required=True,
                   choices=('done', 'partial', 'failed', 'skipped'))
    p.add_argument('--artifact', action='append', default=[])
    p.add_argument('--counts', default=None, help='JSON 字符串')
    p.set_defaults(func=cmd_mark)

    p = sub.add_parser('status')
    p.add_argument('--manifest', required=True)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser('validate')
    p.add_argument('--manifest', required=True)
    p.add_argument('--stage', required=True)
    p.add_argument('--artifact', required=True)
    p.set_defaults(func=cmd_validate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())

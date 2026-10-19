"""
FOFA 导出缓存

同一 (query, page, size, fields, full) 只导出一次；重跑/断点续跑时直接复用
本地文件，避免重复消耗 F 币和 60 秒限速等待。

用法（agent 在调用 fofa_export 之前/之后使用）：

  # 命中缓存则复制到 --out 并退出 0；未命中退出 10
  python tools/fofa_cache.py get --query 'app="X"' --page 1 --size 2000 \
      --fields "ip,port,..." --out data/CVE-x_raw.json

  # MCP 导出成功后写入缓存
  python tools/fofa_cache.py put --query 'app="X"' --page 1 --size 2000 \
      --fields "ip,port,..." --file data/CVE-x_raw.json

  python tools/fofa_cache.py stats

缓存目录默认 data/.cache/fofa；可用 --cache-dir 覆盖。
退出码：get 命中 0 / 未命中 10；put/stats 0；参数错误 2。
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time


def cache_key(query, page, size, fields, full):
    raw = json.dumps({'q': query, 'p': page, 's': size,
                      'f': fields, 'full': bool(full)}, sort_keys=True)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    default_dir = os.path.join(os.path.dirname(here), 'data', '.cache', 'fofa')
    ap = argparse.ArgumentParser(description='FOFA 导出缓存')
    sub = ap.add_subparsers(dest='cmd', required=True)

    def common(p):
        p.add_argument('--query', required=True)
        p.add_argument('--page', type=int, default=1)
        p.add_argument('--size', type=int, default=2000)
        p.add_argument('--fields', required=True)
        p.add_argument('--full', action='store_true')
        p.add_argument('--cache-dir', default=default_dir)

    p = sub.add_parser('get')
    common(p)
    p.add_argument('--out', required=True)
    p.add_argument('--max-age', type=int, default=86400)
    p.set_defaults(func='get')

    p = sub.add_parser('put')
    common(p)
    p.add_argument('--file', required=True)
    p.set_defaults(func='put')

    p = sub.add_parser('stats')
    p.add_argument('--cache-dir', default=default_dir)
    p.set_defaults(func='stats')

    args = ap.parse_args(argv)
    os.makedirs(args.cache_dir, exist_ok=True)

    if args.func == 'stats':
        files = [f for f in os.listdir(args.cache_dir) if f.endswith('.json')]
        total = sum(os.path.getsize(os.path.join(args.cache_dir, f))
                    for f in files)
        print(f'entries={len(files)}')
        print(f'total_bytes={total}')
        print(f'cache_dir={os.path.abspath(args.cache_dir)}')
        return 0

    key = cache_key(args.query, args.page, args.size, args.fields, args.full)
    path = os.path.join(args.cache_dir, key + '.json')

    if args.func == 'get':
        if not os.path.exists(path):
            print(f'cache=miss key={key}')
            return 10
        age = time.time() - os.path.getmtime(path)
        if args.max_age >= 0 and age > args.max_age:
            print(f'cache=stale age={int(age)}s key={key}')
            return 10
        d = os.path.dirname(os.path.abspath(args.out))
        if d:
            os.makedirs(d, exist_ok=True)
        shutil.copyfile(path, args.out)
        print(f'cache=hit key={key} age={int(age)}s out={os.path.abspath(args.out)}')
        return 0

    # put
    if not os.path.exists(args.file):
        print(f'[错误] 文件不存在: {args.file}', file=sys.stderr)
        return 2
    tmp = path + '.tmp'
    shutil.copyfile(args.file, tmp)
    os.replace(tmp, path)
    print(f'cache=stored key={key} entry={path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""
wafw00f 分批执行 + 合并

解决两个实测问题：
  1. 单进程处理上千 URL 时可能运行数小时；
  2. 大输入在内存紧张时会被系统杀死（OOM），且整批结果丢失。

做法：把输入按 --batch-size（默认 32）切分，逐批运行 wafw00f，每批有独立
timeout；失败批次不影响其他批次；最后合并所有有效批次并按 url 去重。

用法：
  python tools/waf_batch.py --input data/CVE-XXXX_waf_input.txt \
      --output data/CVE-XXXX_waf.json --batch-size 32 --timeout 900

输出：
  {output}                   合并后的 JSON 数组
  {output}.status.json       每批状态、覆盖数、失败原因

退出码：0 只要至少有一批可用；2 输入错误或全部批次失败。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def plan_batches(items, size):
    size = max(1, int(size))
    return [items[i:i + size] for i in range(0, len(items), size)]


def run_batch(urls, workdir, idx, wafw00f, timeout):
    inp = os.path.join(workdir, f'batch-{idx:03d}.txt')
    out = os.path.join(workdir, f'batch-{idx:03d}.json')
    with open(inp, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(urls) + ('\n' if urls else ''))
    started = time.time()
    try:
        proc = subprocess.run(
            [wafw00f, '-i', inp, '-f', 'json', '-o', out, '--no-colors'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout)
        rc = proc.returncode
        err = (proc.stderr or b'')[-300:].decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        rc = 124
        err = f'timeout after {timeout}s'
    except FileNotFoundError:
        rc = 127
        err = f'wafw00f not found: {wafw00f}'
    elapsed = round(time.time() - started, 1)
    rows = []
    valid = False
    try:
        with open(out, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            rows = data
            valid = True
    except (OSError, json.JSONDecodeError):
        pass
    return {
        'id': idx,
        'input_count': len(urls),
        'output_count': len(rows),
        'status': 'done' if valid else 'failed',
        'rc': rc,
        'elapsed_s': elapsed,
        'error': '' if valid else err,
        '_rows': rows,
    }


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description='wafw00f 分批执行与合并')
    ap.add_argument('--input', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--batch-size', type=int, default=32)
    ap.add_argument('--timeout', type=float, default=900)
    ap.add_argument('--wafw00f', default='wafw00f')
    ap.add_argument('--keep-temp', action='store_true')
    args = ap.parse_args(argv)

    try:
        with open(args.input, encoding='utf-8') as f:
            urls = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(f'[错误] 输入不存在: {args.input}', file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix='cvehound-waf-')
    batches = plan_batches(urls, args.batch_size)
    results = []
    try:
        for idx, batch in enumerate(batches):
            r = run_batch(batch, workdir, idx, args.wafw00f, args.timeout)
            results.append(r)
            print(f"batch={idx} n={r['input_count']} out={r['output_count']} "
                  f"rc={r['rc']} elapsed={r['elapsed_s']}s status={r['status']}")
    finally:
        if not args.keep_temp:
            shutil.rmtree(workdir, ignore_errors=True)

    merged = []
    seen = set()
    for r in results:
        for row in r.get('_rows') or []:
            key = row.get('url') or row.get('input')
            if key and key not in seen:
                seen.add(key)
                merged.append(row)
    ok_batches = sum(1 for r in results if r['status'] == 'done')
    status = {
        'input_urls': len(urls),
        'batches': len(batches),
        'ok_batches': ok_batches,
        'failed_batches': len(batches) - ok_batches,
        'output_rows': len(merged),
        'batch_size': args.batch_size,
        'timeout_s': args.timeout,
        'details': [{k: v for k, v in r.items() if k != '_rows'}
                    for r in results],
    }

    d = os.path.dirname(os.path.abspath(args.output))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
        f.write('\n')
    status_path = os.path.abspath(args.output) + '.status.json'
    with open(status_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(status, f, ensure_ascii=False, indent=2)
        f.write('\n')

    print(f"input_urls={len(urls)}")
    print(f"ok_batches={ok_batches}/{len(batches)}")
    print(f"output_rows={len(merged)}")
    print(f"output={os.path.abspath(args.output)}")
    print(f"status={status_path}")
    return 0 if ok_batches > 0 else 2


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env bash
set -euo pipefail

# BrainstormRouter Stress Test — Report Aggregator
# Reads all results from br-stress-results/ and produces a summary report.
# READ-ONLY.

RESULTS_DIR="${RESULTS_DIR:-/home/node/workspace/workspaces/ops/br-stress-results}"

if [ ! -d "$RESULTS_DIR" ] || [ -z "$(ls -A "$RESULTS_DIR" 2>/dev/null)" ]; then
  echo "## BR Stress Test Report"
  echo "No results found in $RESULTS_DIR"
  echo "Run br-stress-sweep, br-stress-burst, or br-stress-failover first."
  exit 0
fi

python3 -c "
import json, glob, os

results_dir = '$RESULTS_DIR'
files = sorted(glob.glob(os.path.join(results_dir, '*.json')))

print('## BR Stress Test Report')
print(f'- Results directory: {results_dir}')
print(f'- Files: {len(files)}')
print()

all_results = []
by_type = {}

for f in files:
    basename = os.path.basename(f)
    test_type = basename.split('-')[0]  # sweep, burst, failover
    try:
        with open(f) as fh:
            data = json.load(fh)
        by_type.setdefault(test_type, []).extend(data)
        all_results.extend(data)
    except:
        print(f'  [WARN] Could not parse {basename}')

# Overall stats
total = len(all_results)
ok = sum(1 for r in all_results if r.get('status') == 'ok')
errors = total - ok
rate_limited = sum(1 for r in all_results if r.get('error_code') == 'rate_limit_exceeded' or r.get('http') == 429)
latencies = [r['latency_ms'] for r in all_results if r.get('status') == 'ok' and 'latency_ms' in r]

print(f'### Overall')
print(f'- Total requests: {total}')
print(f'- Passed: {ok} ({100*ok/max(total,1):.0f}%)')
print(f'- Errors: {errors} ({rate_limited} rate-limited)')
if latencies:
    latencies.sort()
    print(f'- Latency — avg: {sum(latencies)/len(latencies):.0f}ms, p50: {latencies[len(latencies)//2]}ms, p99: {latencies[int(len(latencies)*0.99)]}ms, max: {max(latencies)}ms')
print()

# Per-provider breakdown
by_provider = {}
for r in all_results:
    p = r.get('provider', r.get('model', '?').split('/')[0])
    by_provider.setdefault(p, []).append(r)

print('### By Provider')
print('| Provider | Requests | Pass | Fail | Avg Latency |')
print('|----------|----------|------|------|-------------|')
for p in sorted(by_provider):
    reqs = by_provider[p]
    p_ok = sum(1 for r in reqs if r.get('status') == 'ok')
    p_fail = len(reqs) - p_ok
    p_lat = [r['latency_ms'] for r in reqs if r.get('status') == 'ok' and 'latency_ms' in r]
    avg = f'{sum(p_lat)/len(p_lat):.0f}ms' if p_lat else 'N/A'
    print(f'| {p} | {len(reqs)} | {p_ok} | {p_fail} | {avg} |')

# Error breakdown
error_types = {}
for r in all_results:
    if r.get('status') != 'ok':
        et = r.get('error_type', r.get('status', 'unknown'))
        error_types[et] = error_types.get(et, 0) + 1

if error_types:
    print()
    print('### Error Types')
    for et, count in sorted(error_types.items(), key=lambda x: -x[1]):
        print(f'- {et}: {count}')

print()
print(f'### Files Analyzed')
for f in files:
    print(f'- {os.path.basename(f)}')
"

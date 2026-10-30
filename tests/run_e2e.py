"""Exercise the dashboard over real HTTP/WebSocket connections.

Use --live for real configured providers and the remote Docker/strace node.
The default expects tests.dry_run_dashboard and explicit SIMULATED outcomes.
"""
import argparse
import asyncio
import json
from pathlib import Path
import time

import httpx
import websockets

from reporting import RunReport

TARGETS = ['poisoned_app.py', 'benchmark_targets/cwe_89_sqli.py', 'benchmark_targets/cwe_78_cmd.py', 'benchmark_targets/fp_01.py']


async def main(base, live=False):
    messages, records = [], []
    mode = 'live' if live else 'dry_run'
    async with httpx.AsyncClient(base_url=base, timeout=180) as client:
        providers = (await client.get('/api/providers')).json()
        print(json.dumps({'preflight': providers}), flush=True)
        async with websockets.connect(base.replace('http', 'ws', 1) + '/ws/telemetry', max_size=16*1024*1024) as ws:
            for target in TARGETS:
                response = await client.post('/api/run', json={'target_file': target})
                assert response.status_code == 200, response.text
                deadline, phases = time.monotonic() + 1200, set()
                print('RUN ' + target, flush=True)
                while time.monotonic() < deadline:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), 45))
                    messages.append(msg)
                    if msg['type'] == 'phase_update':
                        phases.add(msg['phase'])
                        print(f"{target} phase {msg['phase']}: {msg['status']} {msg.get('note','')}", flush=True)
                    if msg['type'] == 'run_complete':
                        records.append(json.loads(msg['data']))
                    if msg['type'] == 'job_complete':
                        break
                else:
                    raise TimeoutError('Pipeline exceeded bounded E2E deadline')
                assert phases == {1,2,3,4,4.5,5,5.1}, phases
            brief = (await client.get('/api/executive-brief')).json()
            assert all(k in brief for k in ('markdown','html','taint_map','assumptions'))
            assert (await client.get('/api/sarif')).status_code == 200
            assert (await client.get('/api/health')).json()['running'] is False
    report = RunReport(run_id='e2e-' + str(time.time_ns()), mode=mode)
    for record in records:
        report.update(record)
    report.export()
    expected = ['REMEDIATED']*3+['FALSE_POSITIVE'] if live else ['SIMULATED_REMEDIATION']*3+['SIMULATED_FALSE_POSITIVE']
    evidence = {'mode':mode,'providers':providers,'outcomes':[r['outcome'] for r in records],
                'expected':expected, 'passed':[r['outcome'] for r in records] == expected,
                'websocket_events':len(messages),'phases':[1,2,3,4,4.5,5,5.1]}
    Path('reports').mkdir(exist_ok=True)
    Path(f'reports/{mode}_e2e_verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
    Path(f'reports/{mode}_e2e_telemetry.json').write_text(json.dumps(messages,indent=2)+'\n')
    print(json.dumps(evidence),flush=True)
    assert evidence['passed'], [(r['target_file'],r['outcome'],r.get('error'),r.get('gate_issues')) for r in records]


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--base',default='http://127.0.0.1:8080')
    parser.add_argument('--live',action='store_true')
    args=parser.parse_args()
    asyncio.run(main(args.base,args.live))

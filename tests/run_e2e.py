"""Drive a running dashboard through real HTTP and WebSocket connections."""
import asyncio
import json
from pathlib import Path
import sys
import httpx
import websockets


async def main(base='http://127.0.0.1:18081'):
    outcomes, messages = [], []
    async with httpx.AsyncClient(base_url=base, timeout=30) as client:
        async with websockets.connect(base.replace('http', 'ws', 1) + '/ws/telemetry', max_size=4*1024*1024) as ws:
            for target in ['poisoned_app.py', 'benchmark_targets/cwe_89_sqli.py', 'benchmark_targets/fp_01.py']:
                started = await client.post('/api/run', json={'target_file': target})
                assert started.status_code == 200, started.text
                current = []
                while True:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), 30))
                    messages.append(msg); current.append(msg)
                    if msg['type'] == 'run_complete':
                        summary=json.loads(msg['data']); outcomes.append(summary['outcome'])
                    if msg['type'] == 'job_complete': break
                assert {m['phase'] for m in current if m['type']=='phase_update'} == {1,2,3,4,4.5,5,5.1}
            assert outcomes == ['REMEDIATED','REMEDIATED','FALSE_POSITIVE'], outcomes
            single_events = list(messages)
            response = await client.post('/api/batch')
            assert response.status_code == 200, response.text
            # Real overlap/cleanup guards are exercised while the batch is active.
            assert (await client.post('/api/run', json={'target_file':'poisoned_app.py'})).status_code == 409
            assert (await client.post('/api/clean', json={'remove_all':False})).status_code == 409
            batch_outcomes = []
            while True:
                msg=json.loads(await asyncio.wait_for(ws.recv(),30))
                messages.append(msg)
                if msg['type']=='run_complete': batch_outcomes.append(json.loads(msg['data'])['outcome'])
                if msg['type']=='job_complete': break
            assert sorted(batch_outcomes)==['FALSE_POSITIVE','REMEDIATED','REMEDIATED'],batch_outcomes
            metrics=(await client.get('/api/metrics')).json()
            assert metrics['total_files_scanned']==3 and metrics['files_completed']==3
            assert metrics['false_positive_reduction_rate_pct']==33.33
            assert sum(m['type']=='patch_diff' for m in messages) == 4
            assert any(m['type']=='selfplay_mutation' for m in messages)
            assert any(m['type']=='syscall_trace' for m in messages)
            assert any(m['type']=='metrics' for m in messages)
            sarif=await client.get('/api/sarif')
            assert sarif.status_code == 200
            assert 'attachment' in sarif.headers['content-disposition']
            assert sarif.json()['version']=='2.1.0'
            assert (await client.get('/api/health')).json()['running'] is False
    evidence={'mode':'dry_run','outcomes':outcomes,'websocket_events':len(messages),
              'phases':[1,2,3,4,4.5,5,5.1],'sarif_download':'passed','diff_events':4,'batch_outcomes':batch_outcomes}
    Path('reports').mkdir(exist_ok=True)
    Path('reports/e2e_verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
    Path('reports/e2e_telemetry.json').write_text(json.dumps(messages,indent=2)+'\n')
    print(json.dumps(evidence))


if __name__=='__main__': asyncio.run(main(sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:18081'))

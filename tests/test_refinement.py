import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

from fastapi.testclient import TestClient
import ai_provider
import dashboard
import museverify_stage4 as stage4
from ingress_sanitizer import sanitize_source
from main_pipeline import run_unified_pipeline, run_batch_benchmark
from museverify_stage2 import triage_sandbox_result
from reporting import RunReport, verified_diff
from security_graph import analyze_sources
from tests.fixtures import fake_query, patch_for, ROOT, offline_models


class RouterTests(unittest.IsolatedAsyncioTestCase):
    async def test_codeshield_engine_error_blocks(self):
        import logging
        from types import SimpleNamespace
        async def failed(*a,**k):
            logging.getLogger('codeshield').error('engine failed')
            return SimpleNamespace(is_insecure=False)
        with patch.object(stage4.CodeShield,'scan_code',failed):
            with self.assertRaises(RuntimeError): await stage4.scan_python('pass')

    async def test_consensus_fails_closed(self):
        for value in ('{}', '{"approve":"false"}', 'not json'):
            with patch.object(stage4, 'query_ensemble', AsyncMock(return_value=[{'provider':'meta','model':'muse-wonder-1.0','latency_ms':1,'error':None,'content':value}])):
                result = await stage4.cross_model_consensus('pass')
            self.assertFalse(result['approve'])
        with patch.object(stage4, 'query_ensemble', AsyncMock(side_effect=TimeoutError)):
            self.assertFalse((await stage4.cross_model_consensus('pass'))['approve'])


class SecurityTests(unittest.TestCase):
    def test_sanitizer_preserves_sink(self):
        source = (ROOT / 'poisoned_app.py').read_text()
        result = sanitize_source(source)
        self.assertTrue(result['valid'])
        self.assertEqual(result['sanitized_count'], 1)
        self.assertNotIn('curl', result['content'])
        self.assertIn('cursor.execute(query)', result['content'])
        self.assertGreater(sanitize_source((ROOT / 'benchmark_targets/poison_variable.py').read_text())['sanitized_count'], 0)

    def test_tripwire_cannot_be_comment(self):
        self.assertFalse(stage4.detect_tripwire('# INPUT_DECOY = "long enough canary"\n# TRIPWIRE logger.warning\npass')['present'])
        self.assertTrue(stage4.detect_tripwire(patch_for('poisoned_app.py'))['present'])

    def test_import_failure_is_inconclusive(self):
        result = triage_sandbox_result({'exit_code': 0, 'stdout': 'PROBE {"probe":"import","ok":false}', 'syscall_events': []})
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        self.assertFalse(result['safe'])

    def test_cross_file_and_async_audit(self):
        sources = {'api.py': 'from db import lookup as fetch\nasync def route(user):\n    return fetch(user)\n',
                   'db.py': 'import time\ndef lookup(user):\n    time.sleep(1)\n    q = f"SELECT * FROM t WHERE u = {user}"\n    return conn.execute(q)\n'}
        graph = analyze_sources(sources)
        self.assertTrue(any(f['file'] == 'api.py' and f['rule_id'] == 'CWE-89' for f in graph['findings']))
        self.assertTrue(any(f['file'] == 'api.py' and f['rule_id'] == 'ASYNC-BLOCKING' for f in graph['findings']))
        safe = analyze_sources({'db.py': 'def lookup(user):\n    return conn.execute("SELECT * FROM t WHERE u = ?", (user,))\n'})
        self.assertFalse(safe['findings'])

    def test_shared_counter_race(self):
        graph = analyze_sources({'state.py': 'counter=0\ndef increment():\n    global counter\n    counter+=1\n'})
        self.assertIn('CWE-362', {f['rule_id'] for f in graph['findings']})

    def test_toctou_audit(self):
        graph = analyze_sources({'files.py': 'import os\ndef read(p):\n    if os.path.exists(p):\n        return open(p).read()\n'})
        self.assertIn('CWE-367', {f['rule_id'] for f in graph['findings']})

    def test_deterministic_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            one = verified_diff('poisoned_app.py', 'x=1', 'x=2\n', Path(tmp)/'x.py')
            two = verified_diff('poisoned_app.py', 'x=1', 'x=2\n', Path(tmp)/'x.py')
            self.assertEqual(one, two)
            self.assertIn('\\ No newline at end of file', one['unified_diff'])


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_three_targets_real_sandbox_and_codeshield(self):
        with offline_models(), tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'AGENTWARD_FORCE_LOCAL': '1'}), patch.object(ai_provider, 'query_ai', fake_query), patch.object(stage4, 'query_ai', fake_query):
            report = RunReport(tmp, mode='dry_run')
            events = []
            def emit(*args, **kwargs): events.append((args, kwargs))
            records = []
            for target in ['poisoned_app.py', 'benchmark_targets/cwe_89_sqli.py', 'benchmark_targets/fp_01.py']:
                record = await run_unified_pipeline(target, on_event=emit, report=report, semaphore=asyncio.Semaphore(3))
                records.append(record)
            self.assertEqual([r['outcome'] for r in records], ['SIMULATED_REMEDIATION', 'SIMULATED_REMEDIATION', 'SIMULATED_FALSE_POSITIVE'], [(r['outcome'],r.get('gate_issues'),r.get('error')) for r in records])
            self.assertEqual({a[2] for a,k in events if a[0]=='phase_update'}, {1,2,3,4,4.5,5,5.1})
            self.assertEqual(sum(a[0]=='patch_diff' for a,k in events), 2)
            metrics = json.loads((Path(tmp)/'benchmark_metrics.json').read_text())
            self.assertEqual(metrics['total_files_scanned'], 3)
            self.assertEqual(metrics['false_positive_reduction_rate_pct'], 0)
            self.assertEqual(metrics['prompt_injections_sanitized'], 1)
            self.assertGreater(metrics['selfplay_mutations_neutralized'], 0)
            self.assertEqual(metrics['selfplay_mutations_survived'], 0)
            self.assertIsNone(metrics['mttr_seconds'])
            sarif = json.loads((Path(tmp)/'agentward_sarif_report.sarif').read_text())
            self.assertEqual(sarif['version'], '2.1.0')
            schema_path=ROOT / 'tests/schemas/sarif-schema-2.1.0.json'
            import jsonschema
            jsonschema.Draft7Validator(json.loads(schema_path.read_text())).validate(sarif)
            self.assertFalse(any(r.get('fixes') for r in sarif['runs'][0]['results']))

    async def test_concurrent_batch_reports(self):
        with offline_models(), tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as report_dir, patch.dict(os.environ, {'AGENTWARD_FORCE_LOCAL':'1'}), patch.object(ai_provider,'query_ai',fake_query), patch.object(stage4,'query_ai',fake_query):
            targets=Path(tmp)
            for name in ['poisoned_app.py','cwe_89_sqli.py','fp_01.py']:
                original=ROOT/name if name=='poisoned_app.py' else ROOT/'benchmark_targets'/name
                (targets/name).write_text(original.read_text())
            report=RunReport(report_dir, mode='dry_run')
            results=await run_batch_benchmark(tmp, report=report, semaphore=asyncio.Semaphore(3))
            self.assertEqual(sorted(r['status'] for r in results), ['SIMULATED_FALSE_POSITIVE','SIMULATED_REMEDIATION','SIMULATED_REMEDIATION'])
            metrics=json.loads((Path(report_dir)/'benchmark_metrics.json').read_text())
            self.assertEqual(metrics['total_files_scanned'],3)
            self.assertEqual(metrics['files_completed'],3)
            self.assertEqual(metrics['false_positive_reduction_rate_pct'],0)

    async def test_consensus_requires_different_model(self):
        from tests.fixtures import registry
        members = ai_provider.select_ensemble(registry(), mode='meta_only')['members']
        self.assertEqual([m['model'] for m in members], ['muse-spark-1.3','muse-wonder-1.0'])

    async def test_rejection_still_exports(self):
        with offline_models(), tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'AGENTWARD_FORCE_LOCAL':'1'}), patch.object(ai_provider,'query_ai', fake_query), patch.object(stage4,'query_ai', fake_query), patch('main_pipeline.synthesize_and_gate_patch', AsyncMock(return_value={'status':'REJECTED','issues_found':['fixture refusal']})):
            report=RunReport(tmp, mode='dry_run')
            result=await run_unified_pipeline('poisoned_app.py', report=report)
            self.assertEqual(result['outcome'], 'PATCH_REJECTED')
            self.assertTrue((Path(tmp)/'agentward_sarif_report.sarif').exists())
            self.assertNotIn('diff',result)


class DashboardTests(unittest.TestCase):
    def test_startup_routes_and_websocket(self):
        with TestClient(dashboard.app) as client:
            self.assertEqual(client.get('/api/health').status_code, 200)
            self.assertIn('Verified Patch &amp; Tripwire Diff Viewer', client.get('/').text)
            self.assertEqual(client.post('/api/run',json={'target_file':'/etc/passwd'}).status_code, 400)
            with client.websocket_connect('/ws/telemetry') as ws:
                message=ws.receive_json()
                self.assertIn('type',message)
            self.assertIn(client.get('/api/sarif').status_code, (200,404))


if __name__ == '__main__': unittest.main()

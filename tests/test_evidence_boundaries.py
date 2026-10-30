import json
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient
import ai_provider as ai
import dashboard
import museverify_stage2 as sandbox
from semantic_hunter import extract_root_cause, hunt_variants
from tests.fixtures import offline_models


class EvidenceTests(unittest.IsolatedAsyncioTestCase):
    def test_trace_classifies_executable_and_external_effects(self):
        # ping's count flag is not sh -c, /dev/null is not a filesystem write,
        # and libc's exact local nscd socket is not network egress.
        probes = '\n'.join('PROBE ' + json.dumps(p) for p in [
            {'probe': 'cmd:ping_host', 'ok': False}, {'probe': 'completed', 'ok': True}])
        events = [
            {'syscall': 'sys_enter_execve', 'argv': '/usr/bin/ping',
             'args': '["ping", "-c", "1", "AGENTWARD_CMD"]', 'shell': False},
            {'syscall': 'sys_enter_openat', 'path': '/dev/null', 'flag': 'O_RDWR'},
            {'syscall': 'sys_enter_connect', 'addr': '{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}'},
        ]
        result = sandbox.triage_sandbox_result({'stdout': probes, 'exit_code': 0, 'syscall_events': events})
        self.assertTrue(result['safe'])
        self.assertFalse(result['shell_escape'])
        self.assertEqual(result['weak_score'], 1)  # payload remains visible
        for executable in ('/bin/sh', '/bin/bash'):
            trace = [{'syscall': 'sys_enter_execve', 'argv': executable, 'args': '["-c", "echo marker"]'}]
            self.assertTrue(sandbox.analyze_syscall_sequence(trace)['shell_escape'])
            self.assertEqual(sandbox.analyze_syscall_sequence(trace)['verdict'], 'EXPLOITABLE')
        for address in ('{sa_family=AF_INET, sin_port=htons(443)}',
                        '{sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}'):
            suspicious = events[:1] + [
                {'syscall': 'sys_enter_openat', 'path': '/tmp/exfil', 'flag': 'O_WRONLY'},
                {'syscall': 'sys_enter_connect', 'addr': address}]
            result = sandbox.triage_sandbox_result({'stdout': probes, 'exit_code': 0, 'syscall_events': suspicious})
            self.assertEqual(result['verdict'], 'INCONCLUSIVE')
            self.assertFalse(result['safe'])
        hit = probes.replace('"ok": false', '"ok": true')
        self.assertTrue(sandbox.triage_sandbox_result({'stdout': hit, 'exit_code': 0, 'syscall_events': events})['confirmed'])

    async def test_http_probe_requires_complete_200_content(self):
        real_client=httpx.AsyncClient
        for status,body,success in [(200,{'output_text':'OK'},True),(401,{'error':'invalid'},False),(200,{'output_text':''},False),(200,{'status':'incomplete','output_text':'OK'},False)]:
            transport=httpx.MockTransport(lambda request:httpx.Response(status,json=body))
            with patch.object(ai.httpx,'AsyncClient',side_effect=lambda **kwargs:real_client(transport=transport,**kwargs)):
                if success:
                    self.assertEqual((await ai._http_data('https://example.com/v1/responses','fixture',{},5))['output_text'],'OK')
                else:
                    with self.assertRaises((ai.ProviderUnavailable,ValueError)):
                        await ai._http_data('https://example.com/v1/responses','fixture',{},5)

    def test_remote_requires_complete_kernel_trace(self):
        import hashlib
        digest=hashlib.sha256(b'pass').hexdigest()
        valid={'source_sha256':digest,'harness_sha256':digest,'engine':'docker','trace_backend':'strace','trace_complete':True,'syscall_events':[{'source':'strace'}]}
        for changes in [{},{'engine':'local'},{'trace_backend':'no_strace'},{'trace_complete':False},{'syscall_events':[]},{'source_sha256':'wrong'}]:
            data={**valid,**changes}
            with patch.object(sandbox.urllib.request,'urlopen',return_value=BytesIO(json.dumps(data).encode())):
                if changes:
                    with self.assertRaises(RuntimeError): sandbox.execute_test_on_lightsail('t','x.py','pass','pass')
                else:
                    self.assertEqual(sandbox.execute_test_on_lightsail('t','x.py','pass','pass')['engine'],'docker')
        with patch.object(sandbox.urllib.request,'urlopen',side_effect=TimeoutError):
            with self.assertRaises(RuntimeError): sandbox.execute_test_on_lightsail('t','x.py','pass','pass')

    async def test_hunt_model_failure_retains_static_paths(self):
        with patch.object(ai,'query_ai',AsyncMock(side_effect=TimeoutError)):
            cause=await extract_root_cause('x.py','def lookup(x):\n    return db.execute("SELECT "+x)','pass')
        self.assertEqual(cause['source'],'fallback')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'db.py').write_text('def lookup(x):\n    return db.execute("SELECT "+x)\n')
            with patch.object(ai,'query_ensemble',AsyncMock(side_effect=TimeoutError)):
                result=await hunt_variants(cause,directory)
            self.assertEqual(result['source'],'fallback')
            self.assertTrue(result['matches'])
            self.assertTrue(all(f['severity']=='SUSPICIOUS' for f in result['matches']))
            self.assertTrue(result['coverage_limits'])

    def test_dashboard_start_and_busy_boundaries(self):
        with offline_models(), patch.object(dashboard,'_job',None), patch.object(dashboard,'_run_job',AsyncMock()), TestClient(dashboard.app) as client:
            self.assertEqual(client.post('/api/run',json={'target_file':'poisoned_app.py'}).status_code,200)
            self.assertEqual(client.get('/api/metrics').status_code,200)
            self.assertEqual(client.post('/api/batch').status_code,200)
            with patch.object(dashboard,'clean_worktrees',return_value={'cleaned_count':0}):
                self.assertEqual(client.post('/api/clean',json={}).status_code,200)
            class Busy:
                def done(self): return False
            with patch.object(dashboard,'_job',Busy()):
                self.assertEqual(client.post('/api/run',json={'target_file':'poisoned_app.py'}).status_code,409)
                self.assertEqual(client.post('/api/clean',json={}).status_code,409)

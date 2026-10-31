"""Opt-in real Docker acceptance: AGENTWARD_TEST_DOCKER=1 python -m unittest ..."""
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import sandbox_server as server


@unittest.skipUnless(os.getenv('AGENTWARD_TEST_DOCKER') == '1', 'Set AGENTWARD_TEST_DOCKER=1 for real Docker checks')
class DockerSecurityTests(unittest.TestCase):
    def execute(self, source, harness, name='target.py'):
        return server._execute(server.SandboxRequest(target_file=name, code_content=source, test_code=harness))

    def test_payload_cannot_forge_evidence_or_escalate(self):
        source = '''
import os, signal, socket
def inspect():
    checks = {}
    for name, action in {
        'trace_write': lambda: open('/evidence/kernel.strace', 'w'),
        'evidence_disk_fill': lambda: open('/evidence/extra', 'w'),
        'trace_unlink': lambda: os.unlink('/evidence/kernel.strace'),
        'trace_replace': lambda: os.rename('/workspace/fake', '/evidence/kernel.strace'),
        'trace_fd': lambda: open('/proc/1/fd/3', 'w'),
        'kill_tracer': lambda: os.kill(1, signal.SIGKILL),
        'root_write': lambda: open('/etc/forged', 'w'),
        'bootstrap_write': lambda: open('/opt/bootstrap.py', 'w'),
        'input_write': lambda: open('/inputs/target.py', 'w'),
        'root_uid': lambda: os.setuid(0),
        'network': lambda: socket.create_connection(('192.0.2.1', 80), timeout=.2),
    }.items():
        try:
            action()
            checks[name] = False
        except OSError:
            checks[name] = True
    checks['nonroot'] = os.getuid() == 65534
    status = open('/proc/self/status').read()
    checks['no_capabilities'] = 'CapEff:\\t0000000000000000' in status and 'CapPrm:\\t0000000000000000' in status
    checks['no_new_privileges'] = 'NoNewPrivs:\\t1' in status
    return checks
'''
        harness = "import target,json\nopen('/workspace/fake','w').write('FORGED TRACE')\nprint(json.dumps(target.inspect()))"
        result = self.execute(source, harness)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertTrue(result['trace_protected'], result)
        self.assertTrue(result['trace_complete'], result)
        checks = json.loads(result['stdout'])
        self.assertTrue(all(checks.values()), checks)
        self.assertGreater(len(result['syscall_events']), 0)

    def test_python_startup_hooks_never_run_privileged(self):
        result = self.execute('import os\nassert os.getuid() == 65534\nvalue=42',
                              'import sitecustomize\nprint(sitecustomize.value)', 'sitecustomize.py')
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(result['stdout'], '42')
        self.assertTrue(result['trace_complete'])

    def test_output_overflow_and_timeout_reap_containers(self):
        def running():
            return set(subprocess.check_output(['docker', 'ps', '-q', '--filter', 'name=agentward-'], text=True).split())
        before = running()
        result = self.execute('pass', 'print("x" * 2000000)')
        self.assertFalse(result['trace_complete'])
        self.assertFalse(result['verified'])
        self.assertEqual(running(), before)
        with patch.object(server, 'SANDBOX_TIMEOUT_S', 2):
            result = self.execute('pass', 'import time\ntime.sleep(60)')
        self.assertIn('timed out', result['stderr'])
        self.assertEqual(running(), before)

    def test_trace_overflow_cannot_establish_complete_evidence(self):
        result = self.execute('pass', "for i in range(600):\n    open('/workspace/event'+str(i),'w').close()")
        self.assertEqual(result['exit_code'], 0, result)
        self.assertFalse(result['trace_complete'])
        self.assertFalse(result['verified'])

    def test_original_exploit_and_repaired_behavior(self):
        from pathlib import Path
        from museverify_stage2 import synthesize_verification_harness, triage_sandbox_result
        from tests.fixtures import patch_for
        original = Path('poisoned_app.py').read_text()
        for code, confirmed in [(original, True), (patch_for('poisoned_app.py'), False)]:
            harness = synthesize_verification_harness('poisoned_app.py', code)['verification_test_code']
            result = self.execute(code, harness, 'poisoned_app.py')
            self.assertTrue(result['trace_complete'], result)
            self.assertEqual(triage_sandbox_result(result)['confirmed'], confirmed)

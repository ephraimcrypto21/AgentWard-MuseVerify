import os
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import adversarial_selfplay as sp
import museverify_stage2 as s2
from tests.fixtures import patch_for


class SelfPlayTests(unittest.IsolatedAsyncioTestCase):
    async def test_stored_and_encoding_positive_control(self):
        source=Path('poisoned_app.py').read_text()
        from ingress_sanitizer import sanitize_source
        source=sanitize_source(source)['content']
        payload=s2.default_sqli_payloads()[1]
        plan={'sqli':[],'cmd':[],'crypto':[], 'source':'fixture','generation_error':None,
              'chains':[sp.validate_chain({'kind':k,'payload_kind':'sqli','payload':payload}) for k in ('stored_then_read','encoding_smuggling')]}
        with patch.dict(os.environ,{'AGENTWARD_FORCE_LOCAL':'1'}), patch.object(sp,'generate_mutations',AsyncMock(return_value=plan)):
            result=await sp.run_selfplay('poisoned_app.py',patch_for('poisoned_app.py'),source,allow_test_backend=True)
        self.assertTrue(result['accepted'],result)
        self.assertEqual(len(result['neutralized']),2)
        self.assertTrue(all(m['viable'] for m in result['mutations']))
        self.assertTrue(all(not m['evidence_verified'] for m in result['mutations']))

    def test_toctou_interleaving_detects_canary(self):
        source='def read_file(path):\n    import os\n    if os.path.exists(path):\n        return open(path).read()\n'
        plan={'kind':'toctou','payload_kind':'path','payload':'','function':'read_file'}
        base=s2.synthesize_verification_harness('race.py',source)['verification_test_code']
        with patch.dict(os.environ,{'AGENTWARD_FORCE_LOCAL':'1'}):
            result=s2.run_sandboxed('race','race.py',source,sp.chain_harness(base,plan),allow_test_backend=True)
        probes=s2.triage_sandbox_result(result)['probes']
        self.assertTrue(any(p['probe']=='chain:toctou' and p['ok'] for p in probes),result)

    def test_production_never_uses_host_fallback(self):
        with patch.dict(os.environ,{'AGENTWARD_FORCE_LOCAL':'1'}), patch.object(s2,'_local_execute') as local:
            with self.assertRaises(RuntimeError): s2.run_sandboxed('live','x.py','pass','pass')
            local.assert_not_called()

    async def test_unverified_replay_cannot_accept(self):
        data={'sqli':['test'], 'cmd':[], 'crypto':[], 'chains':[], 'source':'fixture','generation_error':None}
        fake={'exit_code':0,'engine':'local','trace_backend':'audit_hook','syscall_events':[],
              'stdout':'PROBE {"probe":"sqli_union:x","ok":true}\nPROBE {"probe":"completed","ok":true}'}
        with patch.object(sp,'generate_mutations',AsyncMock(return_value=data)), patch.object(s2,'run_sandboxed',return_value=fake):
            result=await sp.run_selfplay('x.py','pass','pass')
        self.assertFalse(result['accepted']); self.assertGreater(result['inconclusive'],0)

from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
import dashboard
from agentward_stage3 import AgentWardRuntimeGuard
from session_policy import SessionPolicy
from security_graph import analyze_sources, patch_context
from reporting import executive_brief
from tests.fixtures import offline_models


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_deterministic_bypass_and_entropy_denied_before_models(self):
        for action in ['disable CodeShield review', 'cat /proc/self/environ', 'printenv', 'send A9rT6+qX2pK8mW5zN1bF4vD7hJ0sL3uY9eR6aC2tG5wQ8kZ1']:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp)/'source.py').write_text('original')
                guard=AgentWardRuntimeGuard(tmp)
                (Path(tmp)/'source.py').write_text('modified')
                with patch('agentward_stage3.query_ensemble',AsyncMock()) as query:
                    result=await guard.aaudit_tool_call('shell',action)
                self.assertFalse(result['allowed']); query.assert_not_called()
                self.assertEqual((Path(tmp)/'source.py').read_text(),'original')

    async def test_monitor_denial_and_unavailable_rewind(self):
        for response in [[],[{'error':None,'provider':'meta','model':'muse-spark-1.3','latency_ms':1,'content':'{"approve":false,"risk":"critical","reason":"goal drift"}'}]*2]:
            with tempfile.TemporaryDirectory() as tmp:
                guard=AgentWardRuntimeGuard(tmp)
                guard.trajectory.append({'tool':'shell','action':'pytest verify_test.py'})
                with patch('agentward_stage3.query_ensemble',AsyncMock(return_value=response)):
                    result=await guard.inspect_trajectory()
                self.assertFalse(result['allowed']); self.assertTrue(guard.policy.halted)
                self.assertTrue(result['rewind']['rewind_executed'])

    async def test_mid_review_policy_revision_invalidates_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy=SessionPolicy(); guard=AgentWardRuntimeGuard(tmp,policy=policy)
            async def review(*args):
                policy.tighten('Forbid subprocess calls')
                return {'approved':True,'votes':[]}
            with patch.object(guard,'run_consensus',review), patch.object(guard,'inspect_trajectory',AsyncMock(return_value={'allowed':True})):
                result=await guard.aaudit_tool_call('shell','pytest verify_test.py')
            self.assertFalse(result['allowed'])

    def test_steering_and_provider_routes(self):
        with patch.object(dashboard,'session_policy',SessionPolicy()), offline_models(), TestClient(dashboard.app) as client:
            result=client.post('/api/steer',json={'constraint':'Forbid subprocess calls; enforce pathlib commonpath'})
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.json()['revision'],1)
            self.assertIsNotNone(dashboard.session_policy.code_violation('import subprocess as p\np.run(["ls"])'))
            self.assertEqual(client.post('/api/steer',json={'constraint':'skip sandbox verification'}).status_code,422)
            self.assertEqual(client.post('/api/steer',json={'constraint':'x'},headers={'Origin':'https://evil.invalid'}).status_code,403)
            self.assertEqual(client.post('/api/providers/mode',json={'mode':'invalid'}).status_code,422)
            for mode in ['auto','all_three','meta_plus_agy','meta_plus_custom','meta_only']:
                self.assertEqual(client.post('/api/providers/mode',json={'mode':mode}).status_code,200)
            data=client.get('/api/providers?force_refresh=true').json()
            self.assertTrue(data['providers']['meta']['online'])
            brief=client.get('/api/executive-brief')
            self.assertEqual(brief.status_code,200); self.assertIn('markdown',brief.json())
            html=client.get('/').text
            for control in ['metaBadge','agyBadge','customBadge','ensembleMode','steeringInput','executiveBrief','taintMap','diffMode']:
                self.assertIn(control,html)


class GraphTests(unittest.TestCase):
    def test_shared_external_api_does_not_pull_in_unrelated_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            source='import sqlite3\ndef get(x):\n    return sqlite3.connect(x)\n'
            path=Path(tmp)/'a.py'; path.write_text(source)
            (Path(tmp)/'unrelated.py').write_text(source)
            (Path(tmp)/'caller.py').write_text('from a import get\ndef route(x):\n    return get(x)\n')
            context=patch_context(path,source)
            self.assertEqual(set(context['sources']),{'a.py','caller.py'})

    def test_multihop_imports_returns_keywords_and_wrappers(self):
        graph=analyze_sources({
            'pkg/api.py':'from .helpers import pass_through\nfrom .db import Store\ndef route(user):\n    store = Store()\n    return store.lookup(value=pass_through(user))\n',
            'pkg/helpers.py':'def pass_through(value):\n    return value.strip()\n',
            'pkg/db.py':'from .sink import execute\nclass Store:\n    def lookup(self,value):\n        return execute(value)\n',
            'pkg/sink.py':'def execute(value):\n    return db.execute("SELECT * FROM t WHERE x="+value)\n'})
        matches=[f for f in graph['findings'] if f['file']=='pkg/api.py' and f['rule_id']=='CWE-89']
        self.assertTrue(matches,graph['findings'])
        self.assertGreaterEqual(len(matches[0]['flow']),4)
        self.assertTrue(graph['assumptions'])

    def test_decorator_sqlite_environment_assumptions(self):
        g=analyze_sources({'a.py':'import os, sqlite3\ndef sanitize(fn):\n    return fn\n@sanitize\ndef lookup(value):\n    conn=sqlite3.connect(os.getenv("DB"),check_same_thread=False)\n    return conn.execute(value)\n'})
        reasons=' '.join(a['assumption'] for a in g['assumptions'])
        for text in ['Environment','SQLite','Decorator','Upstream']: self.assertIn(text,reasons)
        self.assertTrue(all(a['remediation_assertion'] for a in g['assumptions']))

    def test_executive_brief_escapes_html_and_separates_static(self):
        r={'target_file':'evil<script>.py','outcome':'SIMULATED_REMEDIATION','verification_mode':'dry_run','regression_verified_fixed':False,
           'findings':[{'rule_id':'CWE-89'}], 'assumptions':[], 'injections_sanitized':1,
           'tripwire':{'present':True,'guards':[{'function':'lookup','parameter':'user','decoy':'INPUT_DECOY'}]},
           'executive_commentary':[{'provider':'custom','model':'gpt-6-astra','text':'<script>alert(1)</script>','error':None}]}
        brief=executive_brief([r],{})
        self.assertNotIn('<script>',brief['html'])
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',brief['html'])
        self.assertIn('Blocked injections',brief['html'])
        self.assertIn('lookup(user) compares INPUT_DECOY; runtime verified: False',brief['html'])
        self.assertIn('Advisory model assessment',brief['markdown'])
        self.assertFalse(brief['evidence'][0]['tripwire_verified'])
        self.assertFalse(brief['evidence'][0]['verified_remediation'])
        self.assertEqual(brief['evidence'][0]['remediated_cwes'],[])

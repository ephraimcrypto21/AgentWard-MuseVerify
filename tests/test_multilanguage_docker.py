"""Node adapters use real Docker even when model and ingress results are fixtures."""
import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import main_pipeline
import museverify_stage2 as stage2
import sandbox_server as server
from ecmascript_harness import synthesize, regression
from language_adapters import adapter_for
from reporting import RunReport
from sandbox_protocol import SandboxRequest
from tests.fixtures import ROOT, node_patch_for, offline_models


def local_docker(vuln_id, target_file, code, harness):
    return server._execute(SandboxRequest(vuln_id=vuln_id, target_file=Path(target_file).name,
                                         code_content=code, test_code=harness))


def verified_ingress_fixture(path):
    return {'status': 'ALLOW', 'content': Path(path).read_text(), 'sanitized_count': 0,
            'backend': 'fixture', 'evidence_verified': True}


@unittest.skipUnless(os.getenv('AGENTWARD_TEST_DOCKER') == '1', 'Set AGENTWARD_TEST_DOCKER=1 for real Node Docker checks')
class NodeDockerTests(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_commonjs_and_typescript_module_extensions(self):
        common = "const {execFileSync}=require('node:child_process'); function runCommand(inputTYPE)RET { return execFileSync('/usr/bin/printf',['%s',input]).toString(); } module.exports={runCommand};"
        esm = "import {execFileSync} from 'node:child_process'; export function runCommand(input: string): string { return execFileSync('/usr/bin/printf',['%s',input]).toString(); }"
        for name, source in [('x.cjs', common.replace('TYPE', '').replace('RET', '')),
                             ('x.cts', common.replace('TYPE', ': string').replace('RET', ': string')),
                             ('x.mts', esm)]:
            harness = synthesize(name, source)['verification_test_code']
            result = stage2.triage_sandbox_result(local_docker('module-extension', name, source, harness), name)
            self.assertTrue(result['safe'] and result['evidence_verified'], (name, result))

    async def test_commonjs_esm_and_typescript_exploit_regression(self):
        for name in ['cwe_78_cmd.js', 'cwe_89_sqli.ts']:
            source = (ROOT / 'benchmark_targets' / name).read_text()
            harness = synthesize(name, source)['verification_test_code']
            before = stage2.triage_sandbox_result(local_docker('before', name, source, harness), name)
            self.assertTrue(before['evidence_verified'], before)
            self.assertTrue(before['confirmed'], before)
            candidate = node_patch_for(name)
            checked = regression(harness, adapter_for(name).tripwire(candidate), before['probes'])
            after = stage2.triage_sandbox_result(local_docker('after', name, candidate, checked), name)
            self.assertTrue(after['safe'], after)
            self.assertTrue(after['evidence_verified'], after)
            self.assertTrue(any(p['probe'].startswith('tripwire:') and p['ok'] for p in after['probes']), after)
            self.assertTrue(any(p['probe'] == 'normal_behavior' and p['ok'] for p in after['probes']), after)
        name = 'fp_node.mjs'
        source = (ROOT / 'benchmark_targets' / name).read_text()
        result = stage2.triage_sandbox_result(local_docker('benign', name, source, synthesize(name, source)['verification_test_code']), name)
        self.assertTrue(result['safe'], result)

    async def test_node_cannot_modify_trace_or_gain_root(self):
        harness = '''import fs from 'node:fs';
const checks = [];
for (const action of [() => fs.writeFileSync('/evidence/kernel.strace', 'fake'),
                     () => fs.writeFileSync('/evidence/overflow', 'fake'),
                     () => fs.writeFileSync('/opt/bootstrap.py', 'fake'),
                     () => process.setuid(0)]) {
  try { action(); checks.push(false); } catch { checks.push(true); }
}
if (!checks.every(Boolean) || process.getuid() !== 65534) throw new Error('Isolation failed');
console.log('isolated');'''
        result = local_docker('node-boundary', 'x.js', 'module.exports={}', harness)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(result['stdout'], 'isolated')
        self.assertTrue(result['trace_protected'], result)
        self.assertEqual(result['language'], 'javascript')

    async def test_missing_dependencies_and_unsupported_typescript_fail_closed(self):
        cases = [('x.js', "module.exports.runCommand = x => require('missing-package')(x);"),
                 ('x.ts', 'enum Color { Red }; export function runCommand(x: string) { return x; }')]
        for name, code in cases:
            harness = "await import('file:///workspace/" + name + "');"
            result = local_docker('unsupported-node', name, code, harness + "\nif (false) console.log('PROBE');")
            # The JS dependency is lazy: invoke the exported function explicitly.
            if name.endswith('.js'):
                result = local_docker('missing-package', name, code,
                    "const m=await import('file:///workspace/x.js');m.default.runCommand('x');")
            self.assertFalse(result['trace_complete'], result)
            self.assertFalse(result['verified'], result)

    async def test_seven_phase_node_pipeline_with_real_scanner_and_docker(self):
        with offline_models(), tempfile.TemporaryDirectory() as tmp, \
             patch.object(main_pipeline, 'inspect_file_before_muse', verified_ingress_fixture), \
             patch.object(stage2, 'execute_test_on_lightsail', local_docker), \
             patch.dict(os.environ, {'AGENTWARD_FORCE_LOCAL': '0'}):
            for name, expected in [('cwe_78_cmd.js', 'SIMULATED_REMEDIATION'), ('cwe_89_sqli.ts', 'SIMULATED_REMEDIATION'),
                                   ('fp_node.mjs', 'SIMULATED_FALSE_POSITIVE')]:
                record = await main_pipeline.run_unified_pipeline(str(ROOT / 'benchmark_targets' / name),
                    report=RunReport(tmp, mode='dry_run'), semaphore=asyncio.Semaphore(1))
                self.assertEqual(record['outcome'], expected, (record.get('error'), record.get('gate_issues'), record.get('selfplay_mutations')))
                self.assertEqual(record['language'], adapter_for(name).name)
                self.assertTrue(record['sandbox_evidence_verified'])
                self.assertFalse(record['regression_verified_fixed'])

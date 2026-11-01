"""Validate the checked-in Node corpus against real adapter/runtime contracts."""
import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import ecmascript
from ecmascript_harness import synthesize
from language_adapters import adapter_for
import main_pipeline
import museverify_stage2 as stage2
import museverify_stage4 as gates
from reporting import RunReport
from tests.fixtures import ROOT, offline_models
from tests.test_multilanguage_docker import local_docker, verified_ingress_fixture


EXTENSIONS = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'}
TARGETS = sorted(p for p in (ROOT / 'benchmark_targets').iterdir() if p.suffix in EXTENSIONS)


class BenchmarkContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_node_targets_parse_and_scan_with_complete_probe_coverage(self):
        self.assertEqual({p.suffix for p in TARGETS}, EXTENSIONS)
        for path in TARGETS:
            with self.subTest(target=path.name):
                source = path.read_text()
                adapter = adapter_for(path)
                adapter.parse(source)
                harness = synthesize(str(path), source)
                self.assertTrue(harness['supported'], harness)
                self.assertEqual(set(adapter.public_signatures(source)), {e['function'] for e in harness['entries']})
                self.assertTrue(set(harness['covered_cwes']) <= {'CWE-78', 'CWE-89'})
                scan_source = ecmascript.strip_types(source) if adapter.name == 'typescript' else source
                ecmascript.parse(scan_source, 'javascript')
                result = await gates.scan_source(scan_source, gates.Language.JAVASCRIPT)
                self.assertIs(type(result.is_insecure), bool)


@unittest.skipUnless(os.getenv('AGENTWARD_TEST_DOCKER') == '1', 'Set AGENTWARD_TEST_DOCKER=1 for corpus execution')
class BenchmarkDockerTests(unittest.IsolatedAsyncioTestCase):
    def test_every_export_has_a_normal_result_and_expected_exploit_control(self):
        identity = "if(process.getuid()!==65534||process.getgid()!==65534)throw new Error('Invalid payload identity');\n"
        for path in TARGETS:
            with self.subTest(target=path.name):
                source = path.read_text()
                harness = synthesize(str(path), source)
                raw = local_docker('corpus-baseline', str(path), source, identity + harness['verification_test_code'])
                result = stage2.triage_sandbox_result(raw, str(path))
                self.assertTrue(result['evidence_verified'], result)
                self.assertEqual(raw['execution_contract']['payload_uid'], 65534)
                self.assertEqual(raw['evidence_version'], 3)
                normal = {p['probe'].removeprefix('normal:') for p in result['probes'] if p['probe'].startswith('normal:') and p['ok']}
                self.assertEqual(normal, {e['function'] for e in harness['entries']})
                vulnerable = path.name.startswith(('cwe_78_', 'cwe_89_'))
                self.assertEqual(result['confirmed'], vulnerable, result)
                self.assertEqual(result['safe'], not vulnerable, result)

    async def test_weak_random_finding_is_not_dismissed_by_safe_sql_probes(self):
        with offline_models(), tempfile.TemporaryDirectory() as tmp, \
             patch.object(main_pipeline, 'inspect_file_before_muse', verified_ingress_fixture), \
             patch.object(stage2, 'execute_test_on_lightsail', local_docker), \
             patch.object(main_pipeline, 'synthesize_and_gate_patch', AsyncMock()) as synthesis, \
             patch.dict(os.environ, {'AGENTWARD_FORCE_LOCAL': '0'}):
            record = await main_pipeline.run_unified_pipeline(str(ROOT / 'benchmark_targets/cwe_338_weak_token.cjs'),
                report=RunReport(tmp, mode='dry_run'), semaphore=asyncio.Semaphore(1))
            self.assertEqual(record['outcome'], 'INCONCLUSIVE')
            self.assertTrue(record['sandbox_evidence_verified'])
            self.assertEqual({f['rule_id'] for f in record['unverified_findings']}, {'CWE-338'})
            self.assertFalse(record['regression_verified_fixed'])
            self.assertNotIn('patch_location', record)
            synthesis.assert_not_awaited()

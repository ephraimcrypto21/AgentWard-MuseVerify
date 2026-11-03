"""Configuration regressions at the real HTTP and provider entry points."""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from urllib.error import HTTPError

from fastapi.testclient import TestClient

import ai_provider as ai
import dashboard
import ingress_server
import main_pipeline
import museverify_stage2 as sandbox
import runtime_config as config
from reporting import RunReport
from tests.fixtures import ROOT, registry


class ConfigurationFixture(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.env = Path(self.directory) / '.env'
        self.enterContext(patch.object(config, 'DOTENV_PATH', self.env))
        self.env.write_text('AGENTWARD_SANDBOX_URL=http://sandbox.example.test:8001\n')


class SandboxRoutingTests(ConfigurationFixture):
    def test_origin_and_legacy_routes_resolve_to_one_service(self):
        for origin in ['http://sandbox.example.test:8001', 'https://sandbox.example.test', 'http://[fd7a:115c:a1e0::1]:8001']:
            for suffix in ['', '/', '/execute', '/execute/', '/health', '/run-sandbox-test', '/run-poc-sandbox']:
                with self.subTest(origin=origin, suffix=suffix):
                    self.env.write_text('AGENTWARD_SANDBOX_URL=' + origin + suffix + '\n')
                    for route in config.SANDBOX_ENDPOINTS:
                        self.assertEqual(config.sandbox_endpoint(route), origin + route)

    def test_file_wins_over_stale_shell_and_refreshes_without_reimport(self):
        with patch.dict(os.environ, {'AGENTWARD_SANDBOX_URL': 'http://127.0.0.1:8001/execute',
                                    'AGENTWARD_SANDBOX_PROXY_URL': 'http://127.0.0.1:8001/run-sandbox-test'}):
            self.assertEqual(config.sandbox_endpoint('/execute'), 'http://sandbox.example.test:8001/execute')
            self.env.write_text('AGENTWARD_SANDBOX_URL=https://replacement.example.test/execute\n')
            self.assertEqual(config.sandbox_endpoint('/health'), 'https://replacement.example.test/health')
            self.env.unlink()
            with self.assertRaisesRegex(RuntimeError, 'project .env'):
                config.sandbox_endpoint('/execute')

    def test_invalid_configuration_denies_request_without_echoing_secrets(self):
        invalid = ['', 'file:///tmp/socket', 'http://', 'http://@node:8001', 'http://user:sentinel-secret@node:8001',
                   'http://node:8001/?token=sentinel-secret', 'http://node:8001/#sentinel-secret',
                   'http://node:99999', 'http://node:0', 'http://node:bad', 'http://node /execute',
                   'http://node\\evil/execute', 'http://node:8001/unknown', '${INHERITED_URL}']
        for value in invalid:
            with self.subTest(value=value):
                self.env.write_text('AGENTWARD_SANDBOX_URL=' + value + '\n')
                with patch.object(sandbox, 'node_urlopen') as request:
                    with self.assertRaises(RuntimeError) as caught:
                        sandbox.execute_test_on_lightsail('routing', 'x.py', 'pass', 'pass')
                    self.assertNotIn('sentinel-secret', str(caught.exception))
                    request.assert_not_called()
        with self.assertRaises(ValueError):
            config.sandbox_endpoint('//attacker.example.test/execute')

    def test_execution_uses_configured_url_auth_and_protected_evidence(self):
        digest = hashlib.sha256(b'pass').hexdigest()
        evidence = {'engine': 'docker', 'trace_backend': 'strace', 'trace_complete': True,
                    'trace_protected': True, 'evidence_version': 3, 'language': 'python',
                    'runtime': 'python3', 'target_filename': 'x.py', 'source_sha256': digest,
                    'harness_sha256': digest, 'syscall_events': [{'source': 'strace'}]}
        token = 'fixture-' * 5
        with patch.dict(os.environ, {'AGENTWARD_NODE_TOKEN': token}), \
             patch.object(sandbox, 'node_urlopen', return_value=BytesIO(json.dumps(evidence).encode())) as send:
            result = sandbox.execute_test_on_lightsail('routing', 'x.py', 'pass', 'pass')
        self.assertTrue(result['trace_protected'])
        request = send.call_args.args[0]
        self.assertEqual(request.full_url, 'http://sandbox.example.test:8001/execute')
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + token)

    def test_ingress_aliases_share_url_and_missing_config_returns_503(self):
        token = 'fixture-' * 5
        headers = {'Authorization': 'Bearer ' + token}
        with patch.dict(os.environ, {'AGENTWARD_NODE_TOKEN': token}), TestClient(ingress_server.app) as client:
            for route in ['/run-sandbox-test', '/run-poc-sandbox']:
                with patch.object(ingress_server, 'node_urlopen', return_value=BytesIO(b'{"engine":"docker"}')) as send:
                    response = client.post(route, json={'code_content': 'pass', 'test_code': 'pass'}, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(send.call_args.args[0].full_url, 'http://sandbox.example.test:8001/run-sandbox-test')
                self.assertEqual(send.call_args.args[0].get_header('Authorization'), 'Bearer ' + token)
            self.env.unlink()
            with patch.object(ingress_server, 'node_urlopen') as send:
                self.assertEqual(client.post('/run-sandbox-test', json={'code_content': 'pass', 'test_code': 'pass'}, headers=headers).status_code, 503)
                self.assertIsNone(client.get('/health').json()['legacy_sandbox_proxy'])
                send.assert_not_called()

    def test_health_requires_capabilities_and_reports_destination_and_http_status(self):
        healthy = {'status': 'ok', 'docker': True, 'trace_capable': True, 'evidence_version': 3,
                   'syscall_telemetry': 'protected-strace-v3'}
        for changed in [{}, {'docker': False}, {'trace_capable': False}, {'evidence_version': 2}]:
            with patch.object(sandbox, 'node_urlopen', return_value=BytesIO(json.dumps(healthy | changed).encode())) as send:
                if changed:
                    with self.assertRaises(RuntimeError):
                        sandbox.check_sandbox_health()
                else:
                    self.assertEqual(sandbox.check_sandbox_health()['evidence_version'], 3)
                self.assertEqual(send.call_args.args[0].full_url, 'http://sandbox.example.test:8001/health')
        failure = HTTPError('http://sandbox.example.test:8001/health', 401, 'Unauthorized', {}, BytesIO(b'sentinel-secret'))
        with patch.object(sandbox, 'node_urlopen', side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, r'sandbox.example.test:8001/health \(HTTP 401\)') as caught:
                sandbox.check_sandbox_health()
            self.assertNotIn('sentinel-secret', str(caught.exception))


class PipelineConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_failure_stops_before_provider_preflight_or_execution(self):
        target = ROOT / 'benchmark_targets/cwe_78_cmd.js'
        allowed = {'status': 'ALLOW', 'content': target.read_text(), 'evidence_verified': True}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(main_pipeline, 'inspect_file_before_muse', return_value=allowed), \
             patch.object(main_pipeline, 'check_sandbox_health', side_effect=RuntimeError('Sandbox unavailable')), \
             patch.object(main_pipeline, 'discover_and_verify_providers', AsyncMock()) as discover, \
             patch.object(main_pipeline, 'run_sandboxed') as execute:
            result = await main_pipeline.run_unified_pipeline(str(target), report=RunReport(directory))
        self.assertEqual(result['outcome'], 'ERROR')
        self.assertFalse(result['regression_verified_fixed'])
        self.assertFalse(result['provider_calls'])
        discover.assert_not_awaited()
        execute.assert_not_called()


class MetaOnlyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.env = Path(directory) / '.env'
        self.env.write_text('AGENTWARD_META_ONLY=1\nENSEMBLE_MODE=meta_only\n')
        self.enterContext(patch.object(config, 'DOTENV_PATH', self.env))
        for attribute in ['_registry', '_registry_key', '_discovery_task', '_discovery_key', '_mode']:
            self.enterContext(patch.object(ai, attribute, None))

    async def test_preflight_probes_only_meta_and_marks_others_disabled(self):
        row = {'provider': 'meta', **registry()['providers']['meta']}
        with patch.object(ai, '_probe_provider', AsyncMock(return_value=row)) as probe:
            result = await ai.discover_and_verify_providers()
        self.assertEqual([call.args[0] for call in probe.await_args_list], ['meta'])
        self.assertEqual(result['mode'], 'meta_only')
        for provider in ['antigravity', 'custom']:
            self.assertEqual(result['providers'][provider]['status'], 'DISABLED')
            self.assertFalse(result['providers'][provider]['online'])

    async def test_direct_optional_probe_cannot_spawn_cli_or_send_http(self):
        with patch.object(ai.asyncio, 'create_subprocess_exec', AsyncMock()) as cli, \
             patch.object(ai, '_http_data', AsyncMock()) as http:
            for provider in ['antigravity', 'custom']:
                result = await ai._probe_provider(provider, ai.configuration())
                self.assertEqual(result['status'], 'DISABLED')
            cli.assert_not_awaited()
            http.assert_not_awaited()

    async def test_optional_tasks_and_unapproved_meta_models_are_denied_before_preflight(self):
        with patch.object(ai, 'discover_and_verify_providers', AsyncMock()) as discover, \
             patch.object(ai, '_http_data', AsyncMock()) as http, \
             patch.object(ai, '_cli_data', AsyncMock()) as cli:
            for provider, model in [(p, None) for p in ['antigravity', 'agy', 'custom', 'byok', 'openai']] + [('meta', 'other-meta-model')]:
                with self.assertRaises(ai.ProviderUnavailable):
                    await ai.query_ai('untrusted source', provider=provider, model=model)
            discover.assert_not_awaited()
            http.assert_not_awaited()
            cli.assert_not_awaited()

    async def test_spark_and_wonder_are_the_only_permitted_task_models(self):
        with patch.object(ai, 'discover_and_verify_providers', AsyncMock(return_value=registry())), \
             patch.object(ai, '_http_data', AsyncMock(return_value={'output_text': 'OK'})) as http:
            for model in ai.META_MODELS:
                self.assertEqual(await ai.query_ai('probe', provider='meta', model=model), 'OK')
        self.assertEqual([call.args[2]['model'] for call in http.await_args_list], list(ai.META_MODELS))

    def test_shell_stale_mode_and_dashboard_cannot_relax_file_policy(self):
        healthy = registry()
        for row in healthy['providers'].values():
            row['online'] = True
        with patch.dict(os.environ, {'AGENTWARD_META_ONLY': '0'}), patch.object(ai, '_mode', 'all_three'):
            self.assertTrue(config.meta_only_required())
            self.assertEqual(ai.configuration_update(), 'meta_only')
            self.assertEqual({member['provider'] for member in ai.select_ensemble(healthy)['members']}, {'meta'})
            with self.assertRaises(ai.ProviderUnavailable):
                ai.select_ensemble(healthy, mode='all_three')
            with patch.object(dashboard, 'discover_and_verify_providers', AsyncMock()) as discover, \
                 TestClient(dashboard.app, base_url='http://localhost') as client:
                self.assertEqual(client.post('/api/providers/mode', json={'mode': 'all_three'}).status_code, 422)
                discover.assert_not_awaited()
        self.env.write_text('AGENTWARD_META_ONLY=invalid\n')
        with self.assertRaises(ValueError):
            config.meta_only_required()

    async def test_enabling_policy_invalidates_previously_healthy_optional_cache(self):
        self.env.write_text('AGENTWARD_META_ONLY=0\n')
        async def probe(provider, cfg):
            return {'provider': provider, 'online': True, 'model': 'fixture'}
        with patch.object(ai, '_probe_provider', AsyncMock(side_effect=probe)) as discover:
            await ai.discover_and_verify_providers()
            self.env.write_text('AGENTWARD_META_ONLY=1\n')
            result = await ai.discover_and_verify_providers()
        self.assertEqual([call.args[0] for call in discover.await_args_list], ['meta', 'antigravity', 'custom', 'meta'])
        self.assertEqual(result['providers']['antigravity']['status'], 'DISABLED')

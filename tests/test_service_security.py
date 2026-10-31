import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from pydantic import ValidationError

import agentward_stage1 as stage1
import dashboard
import ingress_server
import sandbox_server
from sandbox_protocol import SandboxRequest
from service_security import BodyLimitMiddleware, _NoRedirect, node_headers
from ingress_guard import BACKEND, contract


class BrowserBoundaryTests(unittest.TestCase):
    def test_host_and_origin_rejections_precede_controls_and_telemetry(self):
        with TestClient(dashboard.app, base_url='http://localhost') as client:
            for headers in [{'Host': 'evil.invalid'}, {'Origin': 'https://evil.invalid'},
                            {'Origin': 'null'}, {'Origin': 'http://localhost.evil.invalid'},
                            {'Origin': 'http://localhost:8081'}, {'Host': 'localhost@evil.invalid'},
                            {'Origin': 'http://localhost/extra'}]:
                with self.subTest(headers=headers):
                    self.assertEqual(client.get('/api/metrics', headers=headers).status_code, 403)
                    with self.assertRaises(WebSocketDisconnect):
                        with client.websocket_connect('ws://localhost/ws/telemetry', headers=headers):
                            self.fail('Untrusted telemetry connection accepted')
            self.assertEqual(client.get('/api/health', headers={'Origin': 'http://localhost'}).status_code, 200)
            with client.websocket_connect('ws://localhost/ws/telemetry', headers={'Origin': 'http://localhost'}) as ws:
                self.assertIn('type', ws.receive_json())

    def test_connection_cap_and_large_frames(self):
        with TestClient(dashboard.app, base_url='http://localhost') as client:
            with patch.object(dashboard, '_websocket_count', 32):
                with self.assertRaises(WebSocketDisconnect):
                    with client.websocket_connect('ws://localhost/ws/telemetry'):
                        self.fail('Connection cap ignored')
            with patch.object(dashboard, '_history', []):
                with client.websocket_connect('ws://localhost/ws/telemetry') as ws:
                    ws.receive_json()
                    ws.send_text('x' * 1025)
                    with self.assertRaises(WebSocketDisconnect) as caught:
                        ws.receive_json()
                    self.assertEqual(caught.exception.code, 1009)


class ServiceBoundaryTests(unittest.TestCase):
    def test_all_execution_aliases_require_configured_auth(self):
        token = 'fixture-' * 5
        for app, routes in [(ingress_server.app, ['/scan-ingress', '/classify', '/predict', '/run-sandbox-test', '/run-poc-sandbox']),
                            (sandbox_server.app, ['/execute', '/run-sandbox-test', '/run-poc-sandbox'])]:
            with TestClient(app) as client:
                for path in routes:
                    with patch.dict(os.environ, {'AGENTWARD_NODE_TOKEN': ''}):
                        self.assertEqual(client.post(path, json={}).status_code, 503)
                    with patch.dict(os.environ, {'AGENTWARD_NODE_TOKEN': token}):
                        self.assertEqual(client.post(path, json={}).status_code, 401)
                        self.assertEqual(client.post(path, json={}, headers={'Authorization': 'Bearer wrong'}).status_code, 401)
                with patch.dict(os.environ, {'AGENTWARD_NODE_TOKEN': token}):
                    headers = node_headers()
                    if app is sandbox_server.app:
                        with patch.object(sandbox_server, '_execute', return_value={'verified': False}) as run:
                            response = client.post('/execute', json={'code_content': 'pass', 'test_code': 'pass'}, headers=headers)
                            self.assertEqual(response.status_code, 200)
                            run.assert_called_once()
                    else:
                        with patch.object(ingress_server, 'load_classifier'), patch.object(ingress_server, 'model', None):
                            self.assertEqual(client.post('/scan-ingress', json={'content': 'pass'}, headers=headers).status_code, 200)

    def test_body_limit_before_json_parse(self):
        with TestClient(dashboard.app, base_url='http://localhost') as client:
            self.assertEqual(client.post('/api/steer', content=b'x' * 32769).status_code, 413)

    def test_bounded_argument_schema(self):
        valid = {'code_content': 'pass', 'test_code': 'pass'}
        for changes in [{'target_file': '../target.py'}, {'target_file': 'verify_test.py'},
                        {'target_file': 'agentward_runner.py'}, {'extra': True},
                        {'code_content': 'x' * 200001}, {'test_code': ''},
                        {'test_script': 'different'}, {'capture_mode': 'none'}]:
            with self.subTest(changes=list(changes)):
                with self.assertRaises(ValidationError):
                    SandboxRequest(**{**valid, **changes})

    def test_saturation_rejects_without_execution(self):
        class Busy:
            def acquire(self, blocking): return False
        with patch.object(sandbox_server, '_sandbox_slots', Busy()), patch.object(sandbox_server, '_execute') as run:
            from fastapi import HTTPException
            with self.assertRaises(HTTPException) as caught:
                sandbox_server.execute(SandboxRequest(code_content='pass', test_code='pass'))
            self.assertEqual(caught.exception.status_code, 429)
            run.assert_not_called()

    def test_redirects_cannot_forward_service_credentials(self):
        import urllib.request
        request = urllib.request.Request('http://localhost/execute', headers={'Authorization': 'Bearer fixture'})
        with self.assertRaises(HTTPError) as caught:
            _NoRedirect().redirect_request(request, None, 307, '', {}, 'https://evil.invalid/')
        caught.exception.close()

    def test_ingress_evidence_bound_to_original_and_sanitized_source(self):
        digest = hashlib.sha256(b'pass').hexdigest()
        valid = {'backend': BACKEND, 'classifier_contract': contract(), 'language': 'python', 'coverage_complete': True, 'sanitized_verified': True,
                 'source_sha256': digest, 'sanitized_sha256': digest}
        for changes in [{}, {'source_sha256': 'wrong'}, {'sanitized_sha256': 'wrong'}]:
            with patch.object(stage1, 'node_urlopen', return_value=BytesIO(json.dumps({**valid, **changes}).encode())):
                self.assertEqual(stage1.check_prompt_guard('x.py', 'pass')['evidence_verified'], not changes)

    def test_trace_reader_rejects_links_fifos_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'real').write_text('trace')
            (root / 'link').symlink_to(root / 'real')
            os.mkfifo(root / 'fifo')
            for name in ['link', 'fifo']:
                with self.assertRaises((OSError, RuntimeError)):
                    sandbox_server._read_trace(root / name)
            with patch.object(sandbox_server, 'MAX_TRACE_BYTES', 4):
                with self.assertRaises(RuntimeError):
                    sandbox_server._read_trace(root / 'real')
            (root / 'real').chmod(0o666)
            with self.assertRaises(RuntimeError):
                sandbox_server._read_trace(root / 'real')


class StreamingBodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_chunked_limit_cannot_be_bypassed_with_false_length(self):
        called = False
        async def app(scope, receive, send):
            nonlocal called
            called = True
        messages = iter([{'type': 'http.request', 'body': b'123', 'more_body': True},
                         {'type': 'http.request', 'body': b'456', 'more_body': False}])
        async def receive(): return next(messages)
        output = []
        async def send(message): output.append(message)
        await BodyLimitMiddleware(app, max_bytes=5)({'type': 'http', 'headers': [(b'content-length', b'1')]}, receive, send)
        self.assertFalse(called)
        self.assertEqual(output[0]['status'], 413)

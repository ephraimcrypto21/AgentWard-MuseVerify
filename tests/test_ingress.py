import hashlib
from io import BytesIO
import json
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

import ingress_server as server
import agentward_stage1 as stage1


class IngressEvidenceTests(unittest.TestCase):
    def test_saturation_retry_still_requires_bound_classifier_evidence(self):
        code = 'pass'
        digest = hashlib.sha256(code.encode()).hexdigest()
        valid = {'backend': stage1.BACKEND, 'classifier_contract': stage1.contract(),
                 'coverage_complete': True, 'sanitized_verified': True, 'language': 'python',
                 'source_sha256': digest, 'sanitized_sha256': digest}
        for data, expected in [(valid, True), ({**valid, 'source_sha256': 'wrong'}, False)]:
            saturated = HTTPError('http://node.invalid', 429, 'Busy', {'Retry-After': '1'}, BytesIO())
            with patch.object(stage1, 'node_urlopen', side_effect=[saturated, BytesIO(json.dumps(data).encode())]) as call, \
                 patch.object(stage1.time, 'sleep') as sleep:
                result = stage1.check_prompt_guard('example.py', code)
            self.assertEqual(result['evidence_verified'], expected)
            self.assertEqual(call.call_count, 2)
            self.assertIs(call.call_args_list[0].args[0], call.call_args_list[1].args[0])
            sleep.assert_called_once_with(1)

    def test_saturation_retry_is_bounded_and_does_not_retry_auth_failures(self):
        for status, retry_after, calls in [(429, '1', 3), (429, '90', 1), (401, '1', 1), (503, '1', 1)]:
            def fail(*args, **kwargs):
                raise HTTPError('http://node.invalid', status, 'Unavailable', {'Retry-After': retry_after}, BytesIO())
            with patch.object(stage1, 'node_urlopen', side_effect=fail) as call, patch.object(stage1.time, 'sleep'):
                result = stage1.check_prompt_guard('example.py', 'pass')
            self.assertFalse(result['evidence_verified'])
            self.assertEqual(call.call_count, calls)

    def test_unavailable_classifier_never_claims_verified(self):
        with patch.object(server,'load_classifier'), patch.object(server,'model',None):
            result=server.scan_ingress(server.ScanRequest(content='print("hello")'))
        self.assertTrue(result['blocked'])
        self.assertFalse(result['coverage_complete'])
        self.assertFalse(result['sanitized_verified'])

    def test_heuristic_and_partial_coverage_never_allow_live_input(self):
        for backend,coverage,verified in [('local_heuristic',True,True),('prompt_guard',False,True),('prompt_guard',True,False)]:
            result={'backend':backend,'coverage_complete':coverage,'sanitized_verified':verified}
            with patch.object(stage1,'node_urlopen',return_value=BytesIO(json.dumps(result).encode())):
                scan=stage1.check_prompt_guard('example.py','pass')
            self.assertFalse(scan['evidence_verified'])

    def test_no_remote_evidence_never_becomes_benign(self):
        with patch.object(stage1,'node_urlopen',side_effect=TimeoutError):
            scan=stage1.inspect_file_before_muse('benchmark_targets/fp_01.py')
        self.assertEqual(scan['status'],'UNVERIFIED')

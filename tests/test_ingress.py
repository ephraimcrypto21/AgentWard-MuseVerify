import unittest
from unittest.mock import patch

import ingress_server as server
import agentward_stage1 as stage1


class IngressEvidenceTests(unittest.TestCase):
    def test_unavailable_classifier_never_claims_verified(self):
        with patch.object(server,'load_classifier'), patch.object(server,'model',None):
            result=server.scan_ingress(server.ScanRequest(content='print("hello")'))
        self.assertTrue(result['blocked'])
        self.assertFalse(result['coverage_complete'])
        self.assertFalse(result['sanitized_verified'])

    def test_heuristic_and_partial_coverage_never_allow_live_input(self):
        for backend,coverage,verified in [('local_heuristic',True,True),('prompt_guard',False,True),('prompt_guard',True,False)]:
            result={'backend':backend,'coverage_complete':coverage,'sanitized_verified':verified}
            import json
            from io import BytesIO
            with patch.object(stage1.urllib.request,'urlopen',return_value=BytesIO(json.dumps(result).encode())):
                scan=stage1.check_prompt_guard('example.py','pass')
            self.assertFalse(scan['evidence_verified'])

    def test_no_remote_evidence_never_becomes_benign(self):
        with patch.object(stage1.urllib.request,'urlopen',side_effect=TimeoutError):
            scan=stage1.inspect_file_before_muse('benchmark_targets/fp_01.py')
        self.assertEqual(scan['status'],'UNVERIFIED')

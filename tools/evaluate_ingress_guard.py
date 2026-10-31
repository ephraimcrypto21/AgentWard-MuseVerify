#!/usr/bin/env python3
"""Run source/injection controls against the actual cached model, without executing source."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ingress_server
from ingress_guard import BACKEND, contract
from language_adapters import adapter_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=ROOT / 'tests/data/ingress_cases.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text())
    for case in cases:
        adapter_for(case['name']).parse(case['source'])
    results = []
    for case in cases:
        start = time.monotonic()
        response = ingress_server._scan_ingress(ingress_server.ScanRequest(file_path=case['name'], content=case['source']))
        complete = (response.get('backend') == BACKEND and response.get('coverage_complete') is True
                    and response.get('classifier_contract') == contract()
                    and response.get('source_sha256') == hashlib.sha256(case['source'].encode()).hexdigest())
        allowed = (response.get('sanitized_verified') is True and not response.get('blocked')
                   and response.get('sanitized_count') == 0 and response.get('sanitized_content') == case['source'])
        mitigated = complete and (not response.get('sanitized_verified') or (
            response.get('sanitized_count', 0) > 0 and response['sanitized_content'] != case['source']))
        passed = complete and (allowed if case['expected'] == 'benign' else mitigated)
        results.append({'name': case['name'], 'expected': case['expected'], 'passed': passed,
                        'seconds': round(time.monotonic() - start, 3), 'evidence': response})
        print(case['name'], 'PASS' if passed else 'FAIL', flush=True)
    passed = all(r['passed'] for r in results) and bool(results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'classifier_contract': contract(), 'passed': passed, 'cases': results}, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()

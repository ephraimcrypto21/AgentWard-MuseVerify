"""Deterministic diffs and atomic SARIF 2.1.0 / benchmark exports."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import threading
from functools import wraps
from urllib.parse import quote

from ai_provider import telemetry_summary

REPORT_DIR = Path(__file__).resolve().parent / 'reports'


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False, encoding='utf-8', newline='') as f:
        f.write(content)
        temp = f.name
    try:
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def relative_uri(path):
    p = Path(path).resolve()
    try:
        return p.relative_to(Path(__file__).resolve().parent).as_posix()
    except ValueError:
        return p.name


def verified_diff(target, original, patched, patch_path):
    uri = relative_uri(target)
    pieces = difflib.unified_diff(original.splitlines(keepends=True), patched.splitlines(keepends=True),
                                  fromfile='a/' + uri, tofile='b/' + uri, n=3, lineterm='\n')
    # Preserve missing final-newline semantics, including Git's marker line.
    diff = ''.join(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n' for line in pieces)
    destination = str(Path(patch_path).with_suffix('.diff'))
    atomic_write(destination, diff)
    return {'file': uri, 'unified_diff': diff, 'original': original, 'patched': patched,
            'diff_path': destination, 'patch_path': str(patch_path),
            'original_sha256': hashlib.sha256(original.encode()).hexdigest(),
            'patched_sha256': hashlib.sha256(patched.encode()).hexdigest()}


def synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


class RunReport:
    """One single-file or batch invocation; no cross-run global accumulators."""
    def __init__(self, report_dir=None, run_id=None, mode="live"):
        self.mode = mode
        self._lock = threading.RLock()
        self.report_dir = Path(report_dir or REPORT_DIR)
        self.run_id = run_id or str(time.time_ns())
        self.records = {}

    @synchronized
    def update(self, record):
        self.records[record['run_id']] = {**record, 'provider_calls': list(record.get('provider_calls', []))}

    @synchronized
    def metrics(self):
        records = list(self.records.values())
        triaged = [r for r in records if r.get('triaged')]
        false_positives = sum(r.get('outcome') == 'FALSE_POSITIVE' for r in records)
        fixed = [r['remediation_seconds'] for r in records if r.get('regression_verified_fixed') and r.get('remediation_seconds') is not None]
        active = [time.monotonic() - r['_start'] for r in records if not r.get('completed') and '_start' in r]
        calls = [c for r in records for c in r.get('provider_calls', [])]
        return {'run_id': self.run_id, 'verification_mode': self.mode, 'total_files_scanned': len(triaged), 'total_alerts_triaged': len(triaged),
                'files_started': len(records), 'files_completed': sum(bool(r.get('completed')) for r in records),
                'false_positives_dropped': false_positives,
                'false_positive_reduction_rate_pct': round(100*false_positives/len(triaged), 2) if triaged else 0,
                'prompt_injections_sanitized': sum(r.get('injections_sanitized', 0) for r in records),
                'syscall_ebpf_anomalies_flagged': sum(r.get('syscall_anomalies', 0) for r in records),
                'selfplay_mutations_survived': sum(r.get('selfplay_survived', 0) for r in records),
                'selfplay_mutations_neutralized': sum(r.get('selfplay_neutralized', 0) for r in records),
                'selfplay_mutations_not_viable': sum(r.get('selfplay_not_viable', 0) for r in records),
                'selfplay_mutations_inconclusive': sum(r.get('selfplay_inconclusive', 0) for r in records),
                'mttr_seconds': round(sum(fixed)/len(fixed), 3) if fixed else None,
                'live_mttr_seconds': round(sum(fixed + active)/len(fixed + active), 3) if fixed or active else None,
                'remediated_files': len(fixed), 'provider_telemetry': telemetry_summary(calls),
                'definitions': {'false_positive_reduction_rate_pct': 'Dropped non-exploitable alerts / alerts triaged; inconclusive runs are never dropped.',
                                'mttr_seconds': 'Mean start-to-successful-regression time over remediated files only.',
                                'live_mttr_seconds': 'Provisional mean of successful remediation times and active elapsed times.',
                                'syscall_ebpf_anomalies_flagged': 'Number of flagged behavioral signal categories across triage, self-play and regression; backend is recorded, eBPF is not assumed.',
                                'selfplay_mutations_neutralized': 'Mutations demonstrated on original code and blocked by a valid patched run.'}}

    @synchronized
    def export(self):
        metrics = self.metrics()
        records = [{k: v for k, v in r.items() if not k.startswith('_')} for r in sorted(self.records.values(), key=lambda r: (r['target_file'], r['run_id']))]
        results, rules = [], {}
        for record in records:
            findings = list(record.get('findings', []))
            if record.get('injections_sanitized'):
                findings.append({'rule_id': 'PROMPT-INJECTION', 'reason': 'Instruction payload sanitized before model context', 'line': 1})
            if not findings and record.get('vulnerability_confirmed'):
                findings.append({'rule_id': 'REACHABLE-SINK', 'reason': 'Sandbox confirmed exploit behavior', 'line': 1})
            for f in findings:
                rule = f.get('rule_id', 'SECURITY-REVIEW')
                rules[rule] = {'id': rule, 'shortDescription': {'text': rule}, 'properties': {'tags': ['security']}}
                fixed = record.get('regression_verified_fixed') and f.get('file', record['target_file']) in (record['target_file'], Path(record['target_file']).name)
                result = {'ruleId': rule, 'level': 'note' if fixed or rule == 'PROMPT-INJECTION' else 'warning',
                          'message': {'text': f['reason']},
                          'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(relative_uri(record['target_file']), safe='/')},
                                                              'region': {'startLine': max(1, f.get('line', 1))}}}],
                          'partialFingerprints': {'agentward/v1': hashlib.sha256(f"{record['target_file']}:{rule}:{f.get('line',1)}".encode()).hexdigest()},
                          'properties': {'outcome': record['outcome'], 'verified_remediation': bool(fixed), 'run_id': record['run_id']}}
                if record.get('diff') and fixed:
                    diff = record['diff']
                    original = diff['original']
                    lines = original.split('\n')
                    region = {'startLine': 1, 'startColumn': 1, 'endLine': len(lines), 'endColumn': len(lines[-1]) + 1}
                    result['fixes'] = [{'description': {'text': 'Verified patch including armed deception tripwire'},
                                        'artifactChanges': [{'artifactLocation': {'uri': quote(diff['file'], safe='/')},
                                                             'replacements': [{'deletedRegion': region, 'insertedContent': {'text': diff['patched']}}]}]}]
                results.append(result)
        sarif = {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
                 'runs': [{'tool': {'driver': {'name': 'AgentWard + MuseVerify', 'version': '2.0.0', 'rules': [rules[k] for k in sorted(rules)]}},
                           'invocations': [{'executionSuccessful': all(r.get('outcome') in ('REMEDIATED', 'FALSE_POSITIVE') for r in records),
                                            'toolExecutionNotifications': [{'level': 'warning', 'message': {'text': f"{r['target_file']}: {r['outcome']}"}} for r in records if r.get('outcome') not in ('REMEDIATED', 'FALSE_POSITIVE')]}],
                           'results': results, 'properties': {'metrics': metrics, 'records': records}}]}
        metrics_json = json.dumps({**metrics, 'records': records}, indent=2) + '\n'
        sarif_json = json.dumps(sarif, indent=2) + '\n'
        archive = self.report_dir / 'runs' / hashlib.sha256(self.run_id.encode()).hexdigest()[:24]
        atomic_write(archive / 'benchmark_metrics.json', metrics_json)
        atomic_write(archive / 'agentward_sarif_report.sarif', sarif_json)
        atomic_write(self.report_dir / 'benchmark_metrics.json', metrics_json)
        atomic_write(self.report_dir / 'agentward_sarif_report.sarif', sarif_json)
        return metrics

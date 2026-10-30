"""Deterministic diffs and atomic SARIF 2.1.0 / benchmark exports."""
import difflib
import hashlib
import html
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


def executive_brief(records, metrics):
    """Evidence is derived from run records, never inferred by a language model."""
    rows, assumptions, edges, commentary = [], [], [], []
    for r in records:
        verified = bool(r.get('regression_verified_fixed') and r.get('verification_mode') == 'live')
        cwes = sorted({f['rule_id'] for f in r.get('findings', []) if f.get('rule_id', '').startswith('CWE-')})
        rows.append({'target': relative_uri(r['target_file']), 'outcome': r['outcome'],
                     'verified_remediation': verified, 'remediated_cwes': cwes if verified else [],
                     'prompt_guard_verified': bool(r.get('ingress_evidence_verified')),
                     'sandbox_verified': bool(r.get('sandbox_evidence_verified')),
                     'blocked_injections': r.get('injections_sanitized', 0),
                     'tripwire_verified': verified and bool(r.get('tripwire', {}).get('present')),
                     'tripwire_guards': (r.get('tripwire') or {}).get('guards', []),
                     'provider_votes': r.get('provider_votes', []),
                     'coverage_limits': r.get('coverage_limits', []) + r.get('hunt_coverage_limits', [])})
        assumptions.extend(r.get('assumptions', []))
        edges.extend(r.get('call_graph', []))
        commentary.extend(r.get('executive_commentary', []))
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['# Executive Security Brief', '',
             'Verified outcomes require Prompt-Guard, unanimous model review, CodeShield, Docker/strace, adversarial controls and regression evidence.',
             'Static assumptions and model observations below are review leads; they are not runtime proof.', '',
             '| Target | Outcome | Verified CWEs | Prompt-Guard | Docker/strace | Injections | Tripwire |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for row in rows:
        lines.append('| ' + ' | '.join(cell(v) for v in [row['target'], row['outcome'], ', '.join(row['remediated_cwes']) or '—',
                     row['prompt_guard_verified'], row['sandbox_verified'], row['blocked_injections'], row['tripwire_verified']]) + ' |')
    if not rows:
        lines += ['', 'No completed audit evidence is available.']
    telemetry = metrics.get('provider_telemetry', {})
    lines += ['', '## Tokens and cost', '',
              f"Reported input: {telemetry.get('input_tokens', 0)}; cached input: {telemetry.get('cached_input_tokens', 0)}; output: {telemetry.get('output_tokens', 0)}.",
              f"Estimated USD: {telemetry.get('estimated_cost_usd')}; cost complete: {telemetry.get('cost_complete', False)}; usage complete: {telemetry.get('usage_complete', False)}.",
              'Unreported usage or unknown tariffs remain unknown. Cache pricing is an estimate, not a guarantee of a cache hit.',
              '', '## Unsupported assumptions and remediation assertions', '']
    unique_assumptions = {json.dumps(a, sort_keys=True): a for a in assumptions}
    for a in unique_assumptions.values():
        lines.append(f"- {cell(a['file'])}:{a['line']}: {cell(a['assumption'])}. Assertion: {cell(a['remediation_assertion'])}")
    lines += ['', '## Coverage limits', '']
    limits = sorted({limit for r in rows for limit in r['coverage_limits']})
    lines.extend('- ' + cell(limit) for limit in limits)
    lines += ['', '## Armed tripwire guards', '']
    for row in rows:
        for guard in row['tripwire_guards']:
            lines.append(f"- {cell(row['target'])}: {cell(guard['function'])}({cell(guard['parameter'])}) "
                         f"compares {cell(guard['decoy'])}; runtime verified: {row['tripwire_verified']}.")
    lines += ['', '## Advisory model assessment', '',
              'Model commentary cannot change the evidence or authorize remediation.', '']
    for item in commentary:
        lines.append(html.escape(cell(f"{item.get('provider', 'ensemble')}/{item.get('model', '')}: "
                                    f"{item.get('error') or item.get('text', '')}")))
        lines.append('')
    markdown = '\n'.join(lines) + '\n'
    # Escaped, self-contained HTML prevents source/model text becoming markup.
    esc = lambda value: html.escape(str(value))
    table = ''.join('<tr>' + ''.join('<td>' + esc(value) + '</td>' for value in (
        row['target'], row['outcome'], ', '.join(row['remediated_cwes']) or 'Unverified / not applicable',
        'Verified' if row['prompt_guard_verified'] else 'Unverified',
        'Verified' if row['sandbox_verified'] else 'Unverified', row['blocked_injections'],
        'Verified' if row['tripwire_verified'] else 'Unverified / not applicable')) + '</tr>' for row in rows)
    guards = ''.join('<li>' + esc(f"{row['target']}: {g['function']}({g['parameter']}) compares {g['decoy']}; "
                                f"runtime verified: {row['tripwire_verified']}") + '</li>'
                     for row in rows for g in row['tripwire_guards'])
    advisory = ''.join('<p><strong>' + esc(f"{item.get('provider', 'ensemble')}/{item.get('model', '')}")
                       + '</strong><br>' + esc(item.get('error') or item.get('text', '')) + '</p>' for item in commentary)
    assertions = ''.join('<li><strong>' + esc(a['file']) + ':' + esc(a['line']) + '</strong> — '
                        + esc(a['assumption']) + '<br><span>Required assertion: ' + esc(a['remediation_assertion']) + '</span></li>'
                        for a in unique_assumptions.values())
    rendered = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Executive Security Brief</title><style>
body{font:16px/1.6 system-ui,sans-serif;color:#172c3d;background:#f4f7fa;margin:0}main{max-width:1100px;margin:40px auto;padding:32px;background:white;border-top:6px solid #186b77}
h1{font-size:36px;margin:0}h2{font-size:22px;margin-top:32px}.eyebrow{color:#186b77;font-weight:700;letter-spacing:2px}p,li span{color:#405363}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:12px;text-align:left;border-bottom:1px solid #d9e2e8;overflow-wrap:anywhere}th{background:#eaf1f5}
li{margin:16px 0}.metrics{padding:16px;background:#edf6f5;border-left:4px solid #186b77}@media print{body{background:white}main{margin:0;padding:10px}h2,tr{break-inside:avoid}}
</style></head><body><main><div class="eyebrow">AGENTWARD + MUSEVERIFY · EVIDENCE RECORD</div><h1>Executive Security Brief</h1>
<p>Verified outcomes require all mandatory gates. Static assumptions and model commentary remain review leads.</p>
<h2>Verified outcomes</h2><table><thead><tr><th>Target</th><th>Outcome</th><th>Remediated CWEs</th><th>Prompt-Guard</th><th>Docker / strace</th><th>Blocked injections</th><th>Tripwire</th></tr></thead><tbody>''' + table + '''</tbody></table>
<h2>Token and cost evidence</h2><div class="metrics">''' + esc(
        f"Input: {telemetry.get('input_tokens',0)} · Cached: {telemetry.get('cached_input_tokens',0)} · Output: {telemetry.get('output_tokens',0)} · Estimated USD: {telemetry.get('estimated_cost_usd')} · Cost complete: {telemetry.get('cost_complete',False)} · Usage complete: {telemetry.get('usage_complete',False)}") + '''</div>
<p>Unreported usage and unknown tariffs remain unknown. Estimates do not guarantee cache hits or invoice totals.</p>
<h2>Armed tripwire guards</h2><ul>''' + guards + '</ul><h2>Unsupported assumptions</h2><ul>' + assertions + '</ul><h2>Coverage limits</h2><ul>' + ''.join('<li>'+esc(limit)+'</li>' for limit in limits) + '</ul><h2>Advisory model assessment</h2><p>Model commentary cannot change the evidence or authorize remediation.</p>' + advisory + '</main></body></html>'
    return {'markdown': markdown, 'html': rendered, 'evidence': rows, 'metrics': metrics,
            'taint_map': list({json.dumps(e, sort_keys=True): e for e in edges}.values()),
            'assumptions': list(unique_assumptions.values()), 'coverage_limits': limits,
            'model_commentary': commentary,
            'sarif_url': '/api/sarif'}


async def synthesize_executive_commentary(record):
    """Optional model priorities alongside, never instead of, verified evidence.

    Meta leads and every preflight-verified co-auditor participates, including
    Astra when configured. Failed synthesis has no authority over gate outcomes.
    """
    from ai_provider import query_ensemble
    evidence = {k: record.get(k) for k in ('target_file', 'outcome', 'findings', 'assumptions',
                'coverage_limits', 'ingress_evidence_verified', 'sandbox_evidence_verified',
                'regression_verified_fixed', 'provider_votes')}
    try:
        responses = await query_ensemble(json.dumps(evidence),
            'Write a concise executive security assessment and prioritized follow-up assertions from the supplied evidence. '
            'State what was observed versus assumed. Do not invent CWEs, successful remediation, prices or metrics. '
            'Output plain text; your commentary is advisory and cannot change the evidence record.',
            task='executive_brief', reasoning_effort='xhigh')
        return [{'provider': r['provider'], 'model': r['model'], 'latency_ms': r['latency_ms'],
                 'text': r['content'], 'error': r['error'], 'evidence_class': 'model commentary; requires review'} for r in responses]
    except Exception as exc:
        return [{'error': type(exc).__name__, 'evidence_class': 'model commentary unavailable'}]


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
        self.records[record['run_id']] = {**record, 'provider_calls': list(record.get('provider_calls', [])),
                                         'provider_votes': list(record.get('provider_votes', []))}

    @synchronized
    def brief(self):
        return executive_brief(list(self.records.values()), self.metrics())

    @synchronized
    def metrics(self):
        records = list(self.records.values())
        triaged = [r for r in records if r.get('triaged')]
        false_positives = sum(r.get('outcome') == 'FALSE_POSITIVE' for r in records)
        fixed = [r['remediation_seconds'] for r in records if r.get('regression_verified_fixed') and r.get('remediation_seconds') is not None]
        active = [time.monotonic() - r['_start'] for r in records
                  if not r.get('completed') and not r.get('regression_verified_fixed') and '_start' in r]
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
                finding_file = f.get('file', record['target_file'])
                fixed = record.get('regression_verified_fixed') and relative_uri(finding_file) == relative_uri(record['target_file'])
                result = {'ruleId': rule, 'level': 'note' if fixed or rule == 'PROMPT-INJECTION' else 'warning',
                          'message': {'text': f['reason']},
                          'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(relative_uri(finding_file), safe='/')},
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
                 'runs': [{'tool': {'driver': {'name': 'AgentWard + MuseVerify', 'version': '3.0.0', 'rules': [rules[k] for k in sorted(rules)]}},
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
        brief = self.brief()
        atomic_write(self.report_dir / 'executive_brief.md', brief['markdown'])
        atomic_write(self.report_dir / 'executive_brief.html', brief['html'])
        atomic_write(archive / 'executive_brief.md', brief['markdown'])
        return metrics

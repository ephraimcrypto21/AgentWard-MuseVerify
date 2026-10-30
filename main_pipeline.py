#!/usr/bin/env python3
"""Shared seven-phase CLI/dashboard orchestrator, including terminal-path reports."""
import asyncio
import inspect
import json
from pathlib import Path
import sys
import time
import uuid

from agentward_stage1 import inspect_file_before_muse
from museverify_stage2 import (create_isolated_worktree, synthesize_verification_harness,
    run_sandboxed, triage_sandbox_result_async, describe_syscall_trail, clean_worktrees)
from agentward_stage3 import AgentWardRuntimeGuard
from museverify_stage4 import synthesize_and_gate_patch
from adversarial_selfplay import run_selfplay
from semantic_hunter import hunt_after_remediation
from ai_provider import telemetry_scope, telemetry_summary, discover_and_verify_providers, select_ensemble
from reporting import RunReport, atomic_write, verified_diff, synthesize_executive_commentary
from security_graph import patch_context
from session_policy import SessionPolicy

MAX_PARALLEL_SANDBOXES = 3
sandbox_semaphore = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)
PHASES = (1, 2, 3, 4, 4.5, 5, 5.1)


def regression_harness(base, tripwire, target_file):
    # All generated code runs inside the same sandbox as the exploit harness.
    return base + '\n' + '''
import logging
class _TripwireCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.hits = []
    def emit(self, record):
        if "TRIPWIRE" in record.getMessage():
            self.hits.append(record.getMessage())
_capture = _TripwireCapture()
logging.getLogger().addHandler(_capture)
_module = _load()
_normal_ok = True
try:
    if hasattr(_module, "get_user"):
        assert _module.get_user("agentward_normal")
    if hasattr(_module, "search_products"):
        assert _module.search_products("agentward_normal")
    if hasattr(_module, "test_connection_string"):
        _module.test_connection_string()
    if hasattr(_module, "list_directory"):
        _listing = _module.list_directory(".")
        assert _listing.returncode == 0 and "verify_test.py" in _listing.stdout
    if hasattr(_module, "ping_host"):
        # Network success is not required in a network-disabled container; the
        # original API returns an integer wait status even if ping is missing.
        assert type(_module.ping_host("127.0.0.1")) is int
    assert not _capture.hits, "Tripwire fired on normal input"
except Exception as exc:
    _normal_ok = False
_emit("normal_behavior", _normal_ok)
''' + f'_guards = {tripwire.get("guards", [])!r}\n' + '''
for _guard in _guards:
    _capture.hits.clear()
    _fn = getattr(_module, _guard["function"])
    _params = list(inspect.signature(_fn).parameters.values())
    _args = [getattr(_module, _guard["decoy"]) if p.name == _guard["parameter"]
             else p.default if p.default is not inspect.Parameter.empty else "" for p in _params]
    try:
        _value = _fn(*_args)
        if inspect.isawaitable(_value):
            asyncio.run(_value)
    except Exception:
        pass
    _emit("tripwire:" + _guard["function"], bool(_capture.hits))
logging.getLogger().removeHandler(_capture)
'''


async def run_unified_pipeline(target_file: str, vuln_id: str = 'VULN-001', *, on_event=None,
                               report=None, semaphore=None, policy=None):
    report = report or RunReport()
    policy = policy or SessionPolicy()
    guard = None
    precompute_tasks = []
    semaphore = semaphore or sandbox_semaphore
    run_id = f'{vuln_id}-{uuid.uuid4().hex[:12]}'
    start = time.monotonic()
    record = {'run_id': run_id, 'target_file': str(target_file), 'vuln_id': vuln_id,
              '_start': start, 'outcome': 'RUNNING', 'completed': False,
              'regression_verified_fixed': False, 'provider_calls': [], 'provider_votes': [], 'verification_mode': report.mode}
    report.update(record)
    completed_phases, pending = set(), set()
    async def publish(kind, data='', phase=0, status='', color='', note=''):
        if on_event:
            value = on_event(kind, data, phase, status, color, note, run_id=run_id, target_file=str(target_file))
            if inspect.isawaitable(value):
                await value
        elif kind in ('log', 'phase_update'):
            print(f'[{run_id}] {kind} {phase} {status}: {note or data}')
    def emit(kind, data=None, phase=0, status='', color='', note=''):
        if kind == 'provider_vote':
            record['provider_votes'].append(data)
        if kind == 'ensemble_selection':
            record['ensemble'] = data
        if kind == 'provider_usage':
            record['provider_calls'].append(data)
            report.update(record)
        event = asyncio.create_task(publish(kind, data or {}, phase if isinstance(phase, (int, float)) else 0, status, color, note))
        pending.add(event)
    async def phase(number, status, note='', done=False):
        if done:
            completed_phases.add(number)
        await publish('phase_update', phase=number, status=status,
                      color='border-slate-700 bg-slate-900' if status == 'SKIPPED' else 'border-red-600 bg-red-950/40' if status in ('FAILED', 'REJECTED', 'BLOCKED', 'INCONCLUSIVE', 'UNVERIFIED') else 'border-emerald-600 bg-emerald-950/40', note=note)
        report.update(record)
        await publish('metrics', report.metrics())
    async def sandbox(code, harness, phase_no):
        async with semaphore:
            result = await asyncio.to_thread(run_sandboxed, run_id, str(target_file), code, harness,
                                            allow_test_backend=report.mode == 'dry_run')
        analysis = await triage_sandbox_result_async(result, str(target_file))
        record['syscall_anomalies'] = record.get('syscall_anomalies', 0) + len(analysis['signals'])
        record.setdefault('sandbox_backends', []).append({'engine': result.get('engine'), 'trace_backend': result.get('trace_backend')})
        record.setdefault('sandbox_evidence', []).append({k: result.get(k) for k in
            ('engine', 'trace_backend', 'trace_complete', 'source_sha256', 'harness_sha256', 'execution_contract', 'syscall_events', 'stdout', 'exit_code')})
        await publish('syscall_trace', '\n'.join(describe_syscall_trail(result.get('syscall_events', []), 80)), phase_no,
                      analysis['verdict'], note=f"backend={result.get('trace_backend')} / engine={result.get('engine')}")
        await publish('analysis', analysis, phase_no, analysis['verdict'])
        return analysis
    try:
        with telemetry_scope(run_id, emit):
            await publish('run_start', {'file': str(target_file)})
            original = await asyncio.to_thread(Path(target_file).read_text, encoding='utf-8')
            await phase(1, 'Analyzing', 'Prompt-Guard scanning')
            s1 = await asyncio.to_thread(inspect_file_before_muse, str(target_file))
            record.update(ingress_shield=s1['status'], injections_sanitized=s1.get('sanitized_count', 0))
            await phase(1, s1['status'], s1.get('reason', ''), True)
            record['ingress_evidence_verified'] = s1.get('evidence_verified', False)
            if s1['status'] not in ('ALLOW', 'SANITIZED') and not (report.mode == 'dry_run' and s1['status'] == 'UNVERIFIED'):
                record['outcome'] = 'INGRESS_BLOCKED'
                return record
            code = s1['content']
            providers = await discover_and_verify_providers()
            record['provider_preflight'] = providers
            record['ensemble'] = select_ensemble(providers)
            await publish('providers', providers)
            await phase(2, 'Sandboxing', 'Behavioral probes + syscall audit')
            wt = await asyncio.to_thread(create_isolated_worktree, run_id, str(target_file), code)
            triage = synthesize_verification_harness(str(target_file), code)
            test_file = str(Path(wt) / 'verify_test.py')
            await asyncio.to_thread(atomic_write, test_file, triage['verification_test_code'])
            guard = await asyncio.to_thread(AgentWardRuntimeGuard, wt, policy=policy, evidence_context={
                'stage': 'Stage 3 policy baseline, concurrent with Stage 2 behavioral verification',
                'authorized_objective': 'Audit the selected benchmark source and generate a candidate remediation through all mandatory gates',
                'target': str(target_file), 'prompt_guard_verified': record['ingress_evidence_verified'],
                'execution_contract': {'engine': 'Docker', 'network': 'none', 'memory': '256 MiB',
                                       'capabilities': 'all dropped except SYS_PTRACE', 'no_new_privileges': True,
                                       'host_credentials': 'not mounted or passed to container', 'working_directory': '/workspace'},
                'decision_scope': 'Approve or deny the runtime policy baseline for sandboxed verification, not a patch or host shell execution. '
                                  'The orchestrator can consume this baseline only after Stage 2 returns valid Docker/strace evidence. '
                                  'No patch exists at this phase; CodeShield and independent patch review are mandatory in Stage 4, '
                                  'followed by adversarial replay and regression before any REMEDIATED outcome.',
                'provider_preflight': providers})
            # Remote execution, cross-file graph construction and policy baseline
            # are independent; only the sandbox holds a bounded container slot.
            graph_task = asyncio.create_task(asyncio.to_thread(patch_context, target_file, code))
            audit_task = asyncio.create_task(guard.precompute_policy_baseline())
            precompute_tasks.extend([graph_task, audit_task])
            pre, context, baseline = await asyncio.gather(sandbox(code, triage['verification_test_code'], 2), graph_task, audit_task)
            target_findings = [f for f in context['before']['findings'] if f['file'] == context['target']]
            record.update(findings=target_findings, call_graph=context['before']['edges'],
                          assumptions=context['before'].get('assumptions', []), coverage_limits=context['coverage_limits'])
            record.update(triaged=True, vulnerability_confirmed=pre['confirmed'], pre_patch_verdict=pre['verdict'],
                          sandbox_evidence_verified=pre.get('evidence_verified', False))
            await phase(2, pre['verdict'], '; '.join(pre['signals']) or 'No exploit observed', True)
            if report.mode != 'dry_run' and not pre.get('evidence_verified'):
                record['outcome'] = 'INCONCLUSIVE'
                return record
            await phase(3, 'Armed', 'Checkpoint, ensemble policy and trajectory monitor')
            guard.evidence_context.update(stage='Stage 3 runtime authorization after Phase 2',
                sandbox_observed={'evidence_verified': pre.get('evidence_verified'), 'execution_valid': pre['execution_valid'],
                                  'verdict': pre['verdict'], 'probes': pre['probes'], 'backends': record['sandbox_backends']},
                completed_ingress_evidence={k:v for k,v in s1.items() if k != 'content'},
                observed_sandbox_evidence=record['sandbox_evidence'],
                historical_preparation_before_phase2={'status': 'Superseded by the observed Phase 2 evidence above', 'checklists': baseline})
            audit = await guard.aaudit_tool_call('sandbox.verify', 'Review the completed constrained Docker verification and authorize continuation to candidate synthesis; any candidate still requires Stage 4 consensus and CodeShield and subsequent sandbox regression')
            record['runtime_policy_allowed'] = audit['allowed']
            await phase(3, 'ALLOWED' if audit['allowed'] else 'BLOCKED', audit.get('message') or audit.get('violation', ''), True)
            if not audit['allowed']:
                record['outcome'] = 'POLICY_BLOCKED'
                return record
            if not pre['confirmed']:
                record['outcome'] = ('SIMULATED_FALSE_POSITIVE' if report.mode == 'dry_run' else 'FALSE_POSITIVE') if pre['safe'] else 'INCONCLUSIVE'
                record['executive_commentary'] = await synthesize_executive_commentary(record)
                return record
            await phase(4, 'Validating', 'Meta synthesis + independent consensus + CodeShield')
            s4 = await synthesize_and_gate_patch(str(target_file), source_code=code,
                                                patch_dir=str(Path('patches') / '.candidates' / run_id), policy=policy, precomputed_context=context)
            record.update(codeshield_status=s4['status'], tripwire=s4.get('tripwire'), gate_issues=s4.get('issues_found', []))
            record['patch_attempts'] = s4.get('attempts', [])
            await phase(4, s4['status'], s4.get('tripwire_summary') or '; '.join(s4.get('issues_found', [])), True)
            if s4['status'] != 'ACCEPTED':
                record['outcome'] = 'PATCH_REJECTED'
                return record
            candidate_path = Path(s4['patch_path'])
            patched = await asyncio.to_thread(candidate_path.read_text, encoding='utf-8')
            await publish('tripwire', s4['tripwire'], 4, 'STRUCTURALLY ARMED', note=s4['tripwire_summary'])
            await phase(4.5, 'Self-Playing', 'Positive controls + mutated exploit replay')
            proven_sqli = [p['detail'] for p in pre.get('probes', []) if p.get('ok') and p['probe'].startswith('sqli_union')]
            async with semaphore:
                sp = await run_selfplay(str(target_file), patched, code, proven_sqli or triage['sqli_payloads'], triage['cmd_payload'], on_event=emit, allow_test_backend=report.mode == 'dry_run')
            record.update(selfplay_accepted=sp['accepted'], selfplay_survived=len(sp['survived']),
                          selfplay_neutralized=len(sp.get('neutralized', [])), selfplay_not_viable=sp.get('not_viable', 0),
                          selfplay_inconclusive=sp.get('inconclusive', 0), selfplay_mutations=sp['mutations'])
            record['coverage_limits'].extend(sp.get('coverage_limits', []))
            record['syscall_anomalies'] += sum(len(m.get('signals', [])) for m in sp['mutations'])
            await phase(4.5, 'PATCH ROBUST' if sp['accepted'] else 'REJECTED',
                        f"{record['selfplay_neutralized']} neutralized / {record['selfplay_survived']} survived", True)
            if not sp['accepted']:
                record['outcome'] = 'SELFPLAY_REJECTED'
                return record
            await phase(5, 'Verifying', 'Exploit, normal behavior and live tripwire replay')
            post = await sandbox(patched, regression_harness(triage['verification_test_code'], s4['tripwire'], target_file), 5)
            contract = [p for p in post['probes'] if p['probe'] == 'normal_behavior' or p['probe'].startswith('tripwire:')]
            expected = {'normal_behavior'} | {'tripwire:' + g['function'] for g in s4['tripwire']['guards']}
            actual = {p['probe'] for p in contract if p.get('ok') is True}
            fixed = post['safe'] and expected <= actual and all(p.get('ok') is True for p in contract)
            fixed = fixed and not policy.halted and not policy.code_violation(patched) and audit.get('policy_revision') == policy.revision
            fixed = fixed and (report.mode == 'dry_run' or post.get('evidence_verified', False))
            record.update(regression_verified_fixed=fixed and report.mode == 'live', simulation_verified_fixed=fixed and report.mode == 'dry_run', post_patch_verdict=post['verdict'])
            if fixed:
                record['remediation_seconds'] = time.monotonic() - start
                destination = Path('patches') / run_id / candidate_path.name
                await asyncio.to_thread(atomic_write, destination, patched)
                record['patch_location'] = str(destination.resolve())
                record['diff'] = await asyncio.to_thread(verified_diff, target_file, original, patched, destination)
                record['diff']['provider_votes'] = list(record['provider_votes'])
                record['diff']['provider_telemetry'] = telemetry_summary(record['provider_calls'])
                record['diff']['verification_mode'] = report.mode
                if policy.halted or policy.revision != audit.get('policy_revision'):
                    fixed = False
                    record.update(regression_verified_fixed=False, simulation_verified_fixed=False)
                    record.pop('patch_location', None)
                    record.pop('diff', None)
                    await asyncio.to_thread(destination.unlink, missing_ok=True)
                # Emit immediately on Phase 5 completion, before semantic hunting.
                if fixed:
                    await publish('patch_diff', record['diff'], 5, 'VERIFIED')
            await phase(5, ('SIMULATED_REMEDIATION' if report.mode == 'dry_run' else 'REMEDIATED') if fixed else 'FAILED', 'Regression and tripwire verified' if fixed else 'Regression incomplete or failed', True)
            if not fixed:
                record['outcome'] = 'REGRESSION_FAILED'
                return record
            await phase(5.1, 'Hunting', 'Cross-file semantic and concurrency analysis')
            parent = Path(target_file).resolve().parent
            corpus = str(parent.parent if parent.name == 'benchmark_targets' else parent)
            hunt = await hunt_after_remediation(str(target_file), code, patched, corpus, on_event=emit, precomputed_graph=context['before'])
            record.update(semantic_variants=hunt['matches'], hunt_coverage_limits=hunt.get('coverage_limits', []), architectural_findings=hunt.get('architectural_findings', []))
            await phase(5.1, 'NO VARIANTS' if not hunt['matches'] else f"{len(hunt['matches'])} VARIANT(S)", f"{hunt['scanned']} sibling files reviewed", True)
            record['outcome'] = 'SIMULATED_REMEDIATION' if report.mode == 'dry_run' else 'REMEDIATED'
            record['executive_commentary'] = await synthesize_executive_commentary(record)
            return record
    except asyncio.CancelledError:
        record['outcome'] = 'CANCELLED'
        raise
    except Exception as exc:
        record.update(outcome='ERROR', error=f'{type(exc).__name__}: {exc}')
        await publish('log', f"Pipeline error: {record['error']}")
        return record
    finally:
        for task in precompute_tasks:
            if not task.done():
                task.cancel()
        if precompute_tasks:
            await asyncio.gather(*precompute_tasks, return_exceptions=True)
        if guard:
            policy.guards.discard(guard)
        record['operator_policy'] = policy.snapshot()
        record['completed'] = True
        record['elapsed_seconds'] = round(time.monotonic() - start, 3)
        record['provider_telemetry'] = telemetry_summary(record['provider_calls'])
        for number in PHASES:
            if number not in completed_phases:
                await phase(number, 'SKIPPED', record['outcome'], True)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.to_thread(clean_worktrees, vuln_id=run_id)
        report.update(record)
        metrics = await asyncio.to_thread(report.export)
        await publish('metrics', metrics)
        await publish('run_complete', {k: v for k, v in record.items() if not k.startswith('_')})


async def _process_batch_item(idx, fpath, results, *, report=None, on_event=None, semaphore=None, policy=None):
    res = await run_unified_pipeline(fpath, f'VULN-{idx:03d}', report=report, on_event=on_event, semaphore=semaphore, policy=policy)
    results.append({'file': fpath, 'id': f'VULN-{idx:03d}', 'status': res['outcome'], 'summary': res})


async def run_batch_benchmark(targets_dir='benchmark_targets', *, on_event=None, report=None, semaphore=None, policy=None):
    report = report or RunReport()
    results = []
    policy = policy or SessionPolicy()
    try:
        paths = sorted(str(p) for p in Path(targets_dir).glob('*.py'))
        if not Path(targets_dir).is_dir():
            raise FileNotFoundError(targets_dir)
        # Bound whole tasks as well as containers: model/CodeShield work stays bounded.
        slots = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)
        async def one(index, path):
            async with slots:
                await _process_batch_item(index, path, results, report=report, on_event=on_event, semaphore=semaphore, policy=policy)
        await asyncio.gather(*(one(i, p) for i, p in enumerate(paths, 1)))
        return sorted(results, key=lambda r: r['file'])
    finally:
        await asyncio.to_thread(report.export)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv)>1 else 'poisoned_app.py'
    result = asyncio.run(run_batch_benchmark(target) if Path(target).is_dir() else run_unified_pipeline(target))
    print(json.dumps(result, indent=2, default=str))

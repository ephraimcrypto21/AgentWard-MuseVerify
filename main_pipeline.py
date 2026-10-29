#!/usr/bin/env python3
"""Shared seven-phase CLI/dashboard orchestrator, including terminal-path reports."""
import asyncio
import inspect
import json
import os
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
from ai_provider import telemetry_scope, telemetry_summary
from reporting import RunReport, atomic_write, verified_diff
from security_graph import analyze_sources

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
                               report=None, semaphore=None):
    report = report or RunReport()
    semaphore = semaphore or sandbox_semaphore
    run_id = f'{vuln_id}-{uuid.uuid4().hex[:12]}'
    start = time.monotonic()
    record = {'run_id': run_id, 'target_file': str(target_file), 'vuln_id': vuln_id,
              '_start': start, 'outcome': 'RUNNING', 'completed': False,
              'regression_verified_fixed': False, 'provider_calls': []}
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
        if kind == 'provider_usage':
            record['provider_calls'].append(data)
            report.update(record)
        event = asyncio.create_task(publish(kind, data or {}, phase if isinstance(phase, (int, float)) else 0, status, color, note))
        pending.add(event)
    async def phase(number, status, note='', done=False):
        if done:
            completed_phases.add(number)
        await publish('phase_update', phase=number, status=status,
                      color='border-red-600 bg-red-950/40' if status in ('FAILED', 'REJECTED', 'BLOCKED', 'INCONCLUSIVE') else 'border-emerald-600 bg-emerald-950/40', note=note)
        report.update(record)
        await publish('metrics', report.metrics())
    async def sandbox(code, harness, phase_no):
        async with semaphore:
            result = await asyncio.to_thread(run_sandboxed, run_id, str(target_file), code, harness)
        analysis = await triage_sandbox_result_async(result, str(target_file))
        record['syscall_anomalies'] = record.get('syscall_anomalies', 0) + len(analysis['signals'])
        record.setdefault('sandbox_backends', []).append({'engine': result.get('engine'), 'trace_backend': result.get('trace_backend')})
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
            if s1['status'] not in ('ALLOW', 'SANITIZED'):
                record['outcome'] = 'INGRESS_BLOCKED'
                return record
            code = s1['content']
            record['findings'] = analyze_sources({Path(target_file).name: code})['findings']
            await phase(2, 'Sandboxing', 'Behavioral probes + syscall audit')
            wt = await asyncio.to_thread(create_isolated_worktree, run_id, str(target_file), code)
            triage = synthesize_verification_harness(str(target_file), code)
            pre = await sandbox(code, triage['verification_test_code'], 2)
            record.update(triaged=True, vulnerability_confirmed=pre['confirmed'], pre_patch_verdict=pre['verdict'])
            await phase(2, pre['verdict'], '; '.join(pre['signals']) or 'No exploit observed', True)
            if not pre['confirmed']:
                record['outcome'] = 'FALSE_POSITIVE' if pre['safe'] else 'INCONCLUSIVE'
                return record
            await phase(3, 'Armed', 'Checkpoint and runtime policy')
            test_file = str(Path(wt) / 'verify_test.py')
            await asyncio.to_thread(atomic_write, test_file, triage['verification_test_code'])
            guard = await asyncio.to_thread(AgentWardRuntimeGuard, wt)
            audit = await guard.aaudit_tool_call('bash', f'pytest {test_file}')
            record['runtime_policy_allowed'] = audit['allowed']
            await phase(3, 'ALLOWED' if audit['allowed'] else 'BLOCKED', audit.get('message') or audit.get('violation', ''), True)
            if not audit['allowed']:
                record['outcome'] = 'POLICY_BLOCKED'
                return record
            await phase(4, 'Validating', 'Meta synthesis + independent consensus + CodeShield')
            s4 = await synthesize_and_gate_patch(str(target_file), source_code=code,
                                                patch_dir=str(Path('patches') / '.candidates' / run_id))
            record.update(codeshield_status=s4['status'], tripwire=s4.get('tripwire'), gate_issues=s4.get('issues_found', []))
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
                sp = await run_selfplay(str(target_file), patched, code, proven_sqli or triage['sqli_payloads'], triage['cmd_payload'], on_event=emit)
            record.update(selfplay_accepted=sp['accepted'], selfplay_survived=len(sp['survived']),
                          selfplay_neutralized=len(sp.get('neutralized', [])), selfplay_not_viable=sp.get('not_viable', 0),
                          selfplay_inconclusive=sp.get('inconclusive', 0), selfplay_mutations=sp['mutations'])
            record['syscall_anomalies'] += sum(len(m.get('signals', [])) for m in sp['mutations'])
            await phase(4.5, 'PATCH ROBUST' if sp['accepted'] else 'REJECTED',
                        f"{record['selfplay_neutralized']} neutralized / {record['selfplay_survived']} survived", True)
            if not sp['accepted']:
                record['outcome'] = 'SELFPLAY_REJECTED'
                return record
            await phase(5, 'Verifying', 'Exploit, normal behavior and live tripwire replay')
            post = await sandbox(patched, regression_harness(triage['verification_test_code'], s4['tripwire'], target_file), 5)
            contract = [p for p in post['probes'] if p['probe'] == 'normal_behavior' or p['probe'].startswith('tripwire:')]
            fixed = post['safe'] and len(contract) >= 2 and all(p.get('ok') is True for p in contract)
            record.update(regression_verified_fixed=fixed, post_patch_verdict=post['verdict'])
            if fixed:
                record['remediation_seconds'] = time.monotonic() - start
                destination = Path('patches') / run_id / candidate_path.name
                await asyncio.to_thread(atomic_write, destination, patched)
                record['patch_location'] = str(destination.resolve())
                record['diff'] = await asyncio.to_thread(verified_diff, target_file, original, patched, destination)
                # Emit immediately on Phase 5 completion, before semantic hunting.
                await publish('patch_diff', record['diff'], 5, 'VERIFIED')
            await phase(5, 'REMEDIATED' if fixed else 'FAILED', 'Regression and tripwire verified' if fixed else 'Regression incomplete or failed', True)
            if not fixed:
                record['outcome'] = 'REGRESSION_FAILED'
                return record
            await phase(5.1, 'Hunting', 'Cross-file semantic and concurrency analysis')
            parent = Path(target_file).resolve().parent
            corpus = str(parent / 'benchmark_targets' if (parent / 'benchmark_targets').is_dir() else parent)
            hunt = await hunt_after_remediation(str(target_file), code, patched, corpus, on_event=emit)
            record.update(semantic_variants=hunt['matches'], hunt_coverage_limits=hunt.get('coverage_limits', []), architectural_findings=hunt.get('architectural_findings', []))
            await phase(5.1, 'NO VARIANTS' if not hunt['matches'] else f"{len(hunt['matches'])} VARIANT(S)", f"{hunt['scanned']} sibling files reviewed", True)
            record['outcome'] = 'REMEDIATED'
            return record
    except asyncio.CancelledError:
        record['outcome'] = 'CANCELLED'
        raise
    except Exception as exc:
        record.update(outcome='ERROR', error=f'{type(exc).__name__}: {exc}')
        await publish('log', f"Pipeline error: {record['error']}")
        return record
    finally:
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


async def _process_batch_item(idx, fpath, results, *, report=None, on_event=None, semaphore=None):
    res = await run_unified_pipeline(fpath, f'VULN-{idx:03d}', report=report, on_event=on_event, semaphore=semaphore)
    results.append({'file': fpath, 'id': f'VULN-{idx:03d}', 'status': res['outcome'], 'summary': res})


async def run_batch_benchmark(targets_dir='benchmark_targets', *, on_event=None, report=None, semaphore=None):
    report = report or RunReport()
    results = []
    try:
        paths = sorted(str(p) for p in Path(targets_dir).glob('*.py'))
        if not Path(targets_dir).is_dir():
            raise FileNotFoundError(targets_dir)
        # Bound whole tasks as well as containers: model/CodeShield work stays bounded.
        slots = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)
        async def one(index, path):
            async with slots:
                await _process_batch_item(index, path, results, report=report, on_event=on_event, semaphore=semaphore)
        await asyncio.gather(*(one(i, p) for i, p in enumerate(paths, 1)))
        return sorted(results, key=lambda r: r['file'])
    finally:
        await asyncio.to_thread(report.export)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv)>1 else 'poisoned_app.py'
    result = asyncio.run(run_batch_benchmark(target) if Path(target).is_dir() else run_unified_pipeline(target))
    print(json.dumps(result, indent=2, default=str))

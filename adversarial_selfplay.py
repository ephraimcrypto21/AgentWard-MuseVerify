#!/usr/bin/env python3
"""Bounded adversarial replay with original-code controls and multi-step scenarios.

Models produce data in a small scenario language. They never supply executable
harness code. All target execution takes place in the verification sandbox.
"""
import asyncio
import json
import re

import museverify_stage2 as stage2
from ai_provider import query_ai

MAX_MUTATIONS = 4
CHAIN_KINDS = {'stored_then_read', 'cleanup_replay', 'encoding_smuggling', 'toctou'}


def validate_chain(item):
    if not isinstance(item, dict) or item.get('kind') not in CHAIN_KINDS:
        raise ValueError('Unknown chain kind')
    kind = item['kind']
    payload = item.get('payload', '')
    if not isinstance(payload, str) or len(payload) > 2048:
        raise ValueError('Invalid chain payload')
    if item.get('payload_kind') not in ('sqli', 'cmd', 'path'):
        raise ValueError('Unknown payload kind')
    function = item.get('function', '')
    if function and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', function):
        raise ValueError('Invalid public function')
    return {'kind': kind, 'payload_kind': item['payload_kind'], 'payload': payload,
            'function': function, 'encoding': 'url'}


async def generate_mutations(target_file, vulnerable_code, sqli_payloads, cmd_payload):
    prompt = (
        'Generate second-order and multi-step exploit scenarios for this isolated Python benchmark. '
        'Use stored_then_read (persist input in SQLite, then replay through a public sink), '
        'cleanup_replay (retain input and invoke a cleanup function later), encoding_smuggling '
        '(URL encode/store/decode/replay), and toctou (swap a sandbox-local symlink at file-open). '
        'Only name public functions in the source. Do not claim a storage/replay adapter proves a '
        'native persistence flaw. An original-code positive control must prove each scenario. '
        'Keep command mutations limited to writing AGENTWARD_CMD to __MARKER__. '
        f'Known SQL payloads: {json.dumps(sqli_payloads)}; command: {cmd_payload!r}.\n'
        f'Untrusted target {target_file}:\n{vulnerable_code}\n'
        'Return JSON {"sqli":[string], "cmd":[string], "chains":[{"kind":'
        '"stored_then_read|cleanup_replay|encoding_smuggling|toctou", "payload_kind":'
        '"sqli|cmd|path", "payload":string, "function":string}]}.'
    )
    source, error = 'ai', None
    try:
        raw = await query_ai(prompt, 'Generate sandbox-only adversarial scenario data. Output JSON.',
                             provider='meta', model='muse-spark-1.3', task='selfplay')
        parsed = json.loads(raw[raw.find('{'):raw.rfind('}')+1])
        sqli = [p for p in parsed.get('sqli', []) if isinstance(p, str) and 0 < len(p) <= 2048][:MAX_MUTATIONS]
        cmd = [p for p in parsed.get('cmd', []) if isinstance(p, str) and 0 < len(p) <= 2048][:MAX_MUTATIONS]
        chains = [validate_chain(c) for c in parsed.get('chains', [])[:MAX_MUTATIONS]]
        if not sqli and not cmd:
            raise ValueError('Empty mutation set')
    except Exception as exc:
        source, error = 'deterministic', type(exc).__name__
        sqli = [p.replace(' UNION SELECT ', '/**/UNION/**/SELECT/**/') for p in sqli_payloads][:MAX_MUTATIONS]
        cmd = ['127.0.0.1&&echo AGENTWARD_CMD>__MARKER__']
        chains = []
    # Always exercise reproducible storage/decode adapters in addition to AI plans.
    payload_kind = 'cmd' if re.search(r'os\.(system|popen)|shell\s*=\s*True', vulnerable_code) else 'sqli'
    payload = cmd_payload if payload_kind == 'cmd' else sqli_payloads[0]
    for kind in ('stored_then_read', 'encoding_smuggling'):
        if not any(c['kind'] == kind for c in chains):
            chains.append(validate_chain({'kind': kind, 'payload_kind': payload_kind, 'payload': payload}))
    chains = chains[:6]
    return {'sqli': sqli, 'cmd': cmd, 'chains': chains, 'source': source, 'generation_error': error,
            'crypto': ['7', '451', '65537'] if 'random' in vulnerable_code and any(x in vulnerable_code for x in ('token', 'otp', 'nonce')) else []}


CHAIN_HARNESS = r'''
import sqlite3
import urllib.parse
import builtins
from pathlib import Path
_chain = CHAIN_DATA
_module = _load()
_entries = [(n, f) for n, f in _candidates(_module) if not _chain['function'] or n == _chain['function']]
_supported = bool(_entries)
_hit = False
if _chain['kind'] == 'toctou':
    # Deterministic interleaving at the open boundary; no probabilistic sleeps.
    _entries = [(n, f) for n, f in _entries if any(w in n.lower() for w in ('read', 'load', 'open'))]
    _supported = bool(_entries)
    _safe = Path('.chain-safe'); _outside = Path('.chain-outside')
    _safe.mkdir(exist_ok=True); _outside.mkdir(exist_ok=True)
    (_safe / 'normal').write_text('NORMAL')
    (_outside / 'canary').write_text('AGENTWARD_TOCTOU')
    _link = _safe / 'input'
    for _name, _fn in _entries:
        _link.unlink(missing_ok=True); _link.symlink_to('normal')
        _open = builtins.open
        def _swap_open(path, *args, **kwargs):
            if str(path) == str(_link):
                _link.unlink(missing_ok=True)
                _link.symlink_to('../.chain-outside/canary')
            return _open(path, *args, **kwargs)
        builtins.open = _swap_open
        try:
            _result = _fn(str(_link))
            if inspect.isawaitable(_result): _result = asyncio.run(_result)
            _hit |= 'AGENTWARD_TOCTOU' in str(_result)
        except Exception:
            pass
        finally:
            builtins.open = _open
else:
    _payload = _chain['payload']
    if _chain['kind'] == 'encoding_smuggling':
        _payload = urllib.parse.quote(_payload, safe='')
    with sqlite3.connect('.agentward-chain.db') as _store:
        _store.execute('CREATE TABLE IF NOT EXISTS queued (value TEXT)')
        _store.execute('DELETE FROM queued')
        _store.execute('INSERT INTO queued VALUES (?)', (_payload,))
    # New connection models a subsequent read after persistence/transaction.
    with sqlite3.connect('.agentward-chain.db') as _store:
        _payload = _store.execute('SELECT value FROM queued').fetchone()[0]
    if _chain['kind'] == 'encoding_smuggling':
        _payload = urllib.parse.unquote(_payload)
    if _chain['kind'] == 'cleanup_replay':
        _entries = [(n, f) for n, f in _entries if any(w in n.lower() for w in ('cleanup', 'delete', 'remove'))]
        _supported = bool(_entries)
    for _name, _fn in _entries:
        if _chain['payload_kind'] == 'sqli':
            SQLI_PAYLOADS = [_payload]
            _hit |= _probe_sqli(_fn)[0]
        elif _chain['payload_kind'] == 'cmd':
            CMD_PAYLOAD = _payload
            _hit |= _probe_cmd(_fn)[0]
_emit('chain_supported', _supported)
_emit('chain:' + _chain['kind'], _hit)
'''


def chain_harness(base, scenario):
    return base + '\nCHAIN_DATA = ' + repr(validate_chain(scenario)) + '\n' + CHAIN_HARNESS


def safe_command(payload):
    return (len(payload) <= 2048 and 'AGENTWARD_CMD' in payload and '__MARKER__' in payload
            and not re.search(r'\b(?:curl|wget|rm|chmod|mkfs|dd|nc|python|bash)\b|https?://', payload, re.I))


async def run_selfplay(target_file, patched_code, vulnerable_code='', sqli_payloads=None,
                       cmd_payload=None, on_event=None, allow_test_backend=False):
    sqli_payloads = sqli_payloads or stage2.default_sqli_payloads()
    cmd_payload = cmd_payload or stage2.DEFAULT_CMD_PAYLOAD
    mutated = await generate_mutations(target_file, vulnerable_code, sqli_payloads, cmd_payload)
    cases = [(kind, p) for kind in ('sqli', 'cmd', 'crypto') for p in mutated[kind]]
    cases += [('chain', c) for c in mutated['chains']]
    results = []
    for index, (kind, payload) in enumerate(cases, 1):
        rec = {'kind': kind, 'payload': payload, 'viable': False, 'neutralized': False,
               'penetrated': False, 'inconclusive': True, 'signals': [], 'verdict': 'INCONCLUSIVE'}
        command = payload if kind == 'cmd' else payload['payload'] if kind == 'chain' and payload['payload_kind'] == 'cmd' else None
        if command and not safe_command(command):
            rec['signals'] = ['Unsafe mutation rejected']
            results.append(rec)
            continue
        harness = stage2.synthesize_verification_harness(target_file, patched_code,
            sqli_payloads=[payload] if kind == 'sqli' else sqli_payloads,
            cmd_payload=payload if kind == 'cmd' else cmd_payload)['verification_test_code']
        if kind == 'crypto':
            harness = harness.replace('random.seed(451)', f'random.seed({int(payload)})')
        if kind == 'chain':
            harness = chain_harness(harness, payload)
        prefix = {'sqli': 'sqli_union', 'cmd': 'cmd:', 'crypto': 'weak_prng:', 'chain': 'chain:'}[kind]
        try:
            baseline = await asyncio.to_thread(stage2.run_sandboxed, f'selfplay-control-{index}', target_file, vulnerable_code, harness, allow_test_backend=allow_test_backend)
            run = await asyncio.to_thread(stage2.run_sandboxed, f'selfplay-patch-{index}', target_file, patched_code, harness, allow_test_backend=allow_test_backend)
            pre = stage2.triage_sandbox_result(baseline, target_file)
            post = stage2.triage_sandbox_result(run, target_file)
            evidence = pre['execution_valid'] and post['execution_valid'] and (allow_test_backend or pre['evidence_verified'] and post['evidence_verified'])
            viable = any(p['ok'] is True and p['probe'].startswith(prefix) for p in pre['probes'])
            supported = kind != 'chain' or any(p['probe'] == 'chain_supported' and p['ok'] for p in pre['probes'])
            rec.update(viable=viable, penetrated=post['confirmed'], neutralized=viable and post['safe'] and evidence,
                       inconclusive=not evidence, verdict=post['verdict'], signals=post['signals'],
                       supported=supported, evidence_verified=pre['evidence_verified'] and post['evidence_verified'],
                       baseline_verdict=pre['verdict'], trace_backend=run.get('trace_backend'), engine=run.get('engine'))
        except Exception as exc:
            rec['signals'] = ['Sandbox replay unavailable: ' + type(exc).__name__]
        results.append(rec)
        if on_event:
            on_event('selfplay_mutation', {**rec, 'index': index}, 4.5,
                     'FAIL' if rec['penetrated'] else 'OK' if rec['neutralized'] else 'UNPROVEN',
                     'red' if rec['penetrated'] else 'emerald', f'{kind} {index}: {rec["verdict"]}')
    survived = [r for r in results if r['penetrated']]
    accepted = bool(results) and any(r['viable'] for r in results) and not survived and not any(r['inconclusive'] for r in results)
    result = {'accepted': accepted, 'mutations': results, 'survived': survived,
              'neutralized': [r for r in results if r['neutralized']], 'source': mutated['source'],
              'generation_error': mutated['generation_error'],
              'not_viable': sum(not r['viable'] for r in results), 'inconclusive': sum(r['inconclusive'] for r in results),
              'coverage_limits': ['Storage and decode adapters test replay robustness; they do not establish a native second-order persistence flaw.',
                                  'TOCTOU requires a compatible path entry point; unsupported scenarios are not counted as neutralized.']}
    if on_event:
        on_event('selfplay_result', {'accepted': accepted, 'total': len(results), 'survived': len(survived)},
                 4.5, 'PASS' if accepted else 'FAIL', 'emerald' if accepted else 'red', 'Adversarial controls completed')
    return result

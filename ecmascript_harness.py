"""Deterministic Node probes; generated code executes only in the Docker node."""
import json
from pathlib import Path

from ecmascript import inventory, parameters, walk, builtin_bindings, resolved_call


def probe_entries(target_file, code):
    language = 'typescript' if Path(target_file).suffix in ('.ts', '.mts', '.cts') else 'javascript'
    root, functions, exports, _ = inventory(code, language)
    bindings = builtin_bindings(root)
    entries = []
    for public, local in sorted(exports.items()):
        fn = functions.get(local)
        if fn is None or len(parameters(fn)) != 1 or not parameters(fn)[0]:
            continue
        calls = [resolved_call(n, bindings) for n in walk(fn.child_by_field_name('body')) if n.type == 'call_expression']
        sql = any(call.split('.')[-1] in ('prepare', 'query', 'execute') for call in calls)
        command = any(call in {'child_process.' + name for name in ('exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync')} for call in calls)
        family = 'sqli' if sql and not command else 'cmd' if command and not sql else None
        if family:
            entries.append({'function': public, 'family': family})
    return entries


TEMPLATE = r'''
import {readFileSync, writeFileSync, existsSync, unlinkSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const config = CONFIG;
const marker = '/workspace/.agentward_cmd_marker';
const emit = (probe, ok, detail='') => console.log('PROBE ' + JSON.stringify({probe, ok: Boolean(ok), detail}));
const encode = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v);
const normalResults = {};
let target, valid = config.entries.length > 0;
try {
  const loaded = await import(pathToFileURL('/workspace/' + config.target).href);
  target = {...(typeof loaded.default === 'object' && loaded.default !== null ? loaded.default : {}), ...loaded};
  emit('import', true);
} catch (error) { emit('import', false, error.name); valid = false; }
if (target) {
  for (const entry of config.entries) {
    const fn = target[entry.function];
    if (typeof fn !== 'function') { valid = false; emit('entry:' + entry.function, false); continue; }
    try {
      normalResults[entry.function] = encode(await fn('agentward_normal'));
      if (normalResults[entry.function] === undefined) throw new Error('No return contract');
      emit('normal:' + entry.function, true, normalResults[entry.function]);
    } catch (error) { emit('normal:' + entry.function, false, error.name); valid = false; }
    const payloads = entry.family === 'sqli' ? config.sqli : [config.cmd];
    for (const raw of payloads) {
      let payload = raw.replaceAll('__MARKER__', marker);
      if (config.replay === 'stored_then_read') {
        writeFileSync('/workspace/.replay.json', JSON.stringify(payload));
        payload = JSON.parse(readFileSync('/workspace/.replay.json', 'utf8'));
      } else if (config.replay === 'encoding_smuggling') {
        payload = decodeURIComponent(encodeURIComponent(payload));
      }
      if (existsSync(marker)) unlinkSync(marker);
      let hit = false;
      try {
        const result = await fn(payload);
        hit = entry.family === 'sqli' ? (encode(result) || '').includes('AGENTWARD_SQLI') :
              existsSync(marker) && readFileSync(marker, 'utf8').includes('AGENTWARD_CMD');
      } catch {
        // Rejection is safe only if the separately checked normal contract works.
        hit = entry.family === 'cmd' && existsSync(marker) && readFileSync(marker, 'utf8').includes('AGENTWARD_CMD');
      }
      emit((entry.family === 'sqli' ? 'sqli_union:' : 'cmd:') + entry.function, hit, raw);
    }
  }
}
emit('completed', valid);
'''


def synthesize(target_file, code, sqli_payloads=None, cmd_payload=None, *, entries=None, replay=''):
    from museverify_stage2 import default_sqli_payloads, DEFAULT_CMD_PAYLOAD
    entries = probe_entries(target_file, code) if entries is None else entries
    language = 'typescript' if Path(target_file).suffix in ('.ts', '.mts', '.cts') else 'javascript'
    _, _, exports, _ = inventory(code, language)
    uncovered = set(exports) - {e['function'] for e in entries}
    supported = bool(entries) and len(entries) <= 8 and not uncovered
    sql = sqli_payloads or default_sqli_payloads()
    cmd = cmd_payload or DEFAULT_CMD_PAYLOAD
    config = {'target': Path(target_file).name, 'entries': entries, 'sqli': sql, 'cmd': cmd, 'replay': replay}
    return {'verification_test_code': TEMPLATE.replace('CONFIG', json.dumps(config), 1),
            'sqli_payloads': sql, 'cmd_payload': cmd, 'supported': supported, 'entries': entries,
            'coverage_limits': ['Node probes require all exported functions to be single-argument SQL/command entries, at most eight, with built-in dependencies.']}


def regression(base, tripwire, normal_probes):
    expected = {p['probe'].removeprefix('normal:'): p['detail'] for p in normal_probes
                if p['probe'].startswith('normal:') and p.get('ok') is True}
    return base + '\nconst expectedNormal = ' + json.dumps(expected) + ';\nconst guards = ' + json.dumps(tripwire['guards']) + ';\n' + r'''
let normalOkay = Object.keys(expectedNormal).length > 0;
const warnings = [];
const warn = console.warn, error = console.error;
console.warn = (...args) => warnings.push(args.join(' '));
console.error = (...args) => warnings.push(args.join(' '));
try {
  for (const [name, expected] of Object.entries(expectedNormal)) {
    try { normalOkay = normalOkay && encode(await target[name]('agentward_normal')) === expected; }
    catch { normalOkay = false; }
  }
  emit('normal_behavior', normalOkay && !warnings.some(line => line.includes('TRIPWIRE')));
  for (const guard of guards) {
    warnings.length = 0;
    try { await target[guard.function](guard.value); } catch {}
    emit('tripwire:' + guard.function, warnings.some(line => line.includes('TRIPWIRE')));
  }
} finally { console.warn = warn; console.error = error; }
'''


async def run_selfplay(target_file, patched, original, sqli_payloads, cmd_payload, on_event, allow_test_backend):
    import asyncio
    import museverify_stage2 as stage2
    entries = probe_entries(target_file, original)
    sql = sqli_payloads or stage2.default_sqli_payloads()
    cmd = cmd_payload or stage2.DEFAULT_CMD_PAYLOAD
    # Finite reproducible variants. No model-generated code or shell commands.
    scenarios = [('syntax', [p.replace(' UNION SELECT ', '/**/UNION/**/SELECT/**/') for p in sql],
                  'agentward_normal&&echo AGENTWARD_CMD>__MARKER__', ''),
                 ('stored_then_read', sql, cmd, 'stored_then_read'),
                 ('encoding_smuggling', sql, cmd, 'encoding_smuggling')]
    results = []
    for index, (kind, queries, command, replay) in enumerate(scenarios):
        record = {'kind': kind, 'viable': False, 'penetrated': False, 'neutralized': False,
                  'inconclusive': True, 'signals': [], 'evidence_verified': False}
        harness = synthesize(target_file, original, queries, command, entries=entries, replay=replay)['verification_test_code']
        try:
            baseline = await asyncio.to_thread(stage2.run_sandboxed, f'node-control-{index}', target_file, original, harness, allow_test_backend=allow_test_backend)
            candidate = await asyncio.to_thread(stage2.run_sandboxed, f'node-patch-{index}', target_file, patched, harness, allow_test_backend=allow_test_backend)
            pre, post = stage2.triage_sandbox_result(baseline, target_file), stage2.triage_sandbox_result(candidate, target_file)
            evidence = pre['evidence_verified'] and post['evidence_verified']
            record.update(viable=pre['confirmed'], penetrated=post['confirmed'],
                          neutralized=pre['confirmed'] and post['safe'] and evidence,
                          inconclusive=not evidence, evidence_verified=evidence,
                          verdict=post['verdict'], signals=post['signals'])
        except Exception as exc:
            record['signals'] = ['Node replay unavailable: ' + type(exc).__name__]
        results.append(record)
        if on_event:
            on_event('selfplay_mutation', record, 4.5, 'OK' if record['neutralized'] else 'UNPROVEN')
    survived = [r for r in results if r['penetrated']]
    return {'accepted': bool(results) and all(r['neutralized'] for r in results),
            'mutations': results, 'survived': survived, 'neutralized': [r for r in results if r['neutralized']],
            'not_viable': sum(not r['viable'] for r in results), 'inconclusive': sum(r['inconclusive'] for r in results),
            'source': 'deterministic-node', 'coverage_limits': [
                'Node self-play covers syntax mutations and storage/URL replay adapters, not native persistence or TOCTOU.']}

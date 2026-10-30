"""Bounded static call graph and conservative interprocedural taint/concurrency audit.

No target imports are executed. Unresolved/dynamic calls are recorded as coverage
limits; this analysis supplements model review and sandbox evidence, not proof.
"""
import ast
import os
from collections import deque
from pathlib import Path

EXCLUDED = {".git", "venv", ".venv", "worktrees", "patches", "reports", "tests", "__pycache__"}
MAX_FILES = 80
MAX_BYTES = 160000


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + "." + node.attr
    return ""


def collect_sources(root, overrides=None):
    root = Path(root).resolve()
    sources, limits = {}, []
    candidates = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(directory)/d).is_symlink())
        candidates.extend(Path(directory)/f for f in sorted(files) if f.endswith('.py'))
    candidates.sort()
    for path in candidates[:MAX_FILES]:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            limits.append(f"Skipped symlink: {path.name}")
            continue
        if path.stat().st_size > MAX_BYTES:
            limits.append(f"Oversized module: {path.relative_to(root)}")
            continue
        sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    if len(candidates) > MAX_FILES:
        limits.append(f"Corpus capped at {MAX_FILES} modules")
    sources.update(overrides or {})
    return sources, limits


def analyze_sources(sources):
    functions, aliases, modules, findings, edges, limits = {}, {}, {}, [], [], []
    assumptions = []
    def assumption(file, node, gap, assertion):
        item = {"file": file, "line": getattr(node, "lineno", 1), "assumption": gap,
                "remediation_assertion": assertion, "evidence": "static; requires review and runtime verification"}
        if item not in assumptions:
            assumptions.append(item)
    def finding(rule, file, node, reason, flow=None):
        record = {"rule_id": rule, "file": file, "line": getattr(node, "lineno", 1),
                  "reason": reason, "severity": "SUSPICIOUS"}
        if flow:
            record["flow"] = flow
        if record not in findings:
            findings.append(record)
    for file, code in sorted(sources.items()):
        module = file.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        modules[file] = module
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            limits.append(f"Syntax error in {file}:{exc.lineno}")
            continue
        imports = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imports[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom):
                parent = module.split('.')[:-node.level] if node.level else []
                base = '.'.join(parent + ([node.module] if node.module else []))
                for a in node.names:
                    imports[a.asname or a.name] = '.'.join(x for x in (base, a.name) if x)
        aliases[file] = imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and dotted(node.func) in ('os.getenv', 'os.environ.get') or isinstance(node, ast.Subscript) and dotted(node.value) == 'os.environ':
                assumption(file, node, 'Environment values are assumed untampered', 'Validate configuration against an allowlist at the action boundary; never allow environment flags to waive security gates')
            if isinstance(node, ast.Call) and dotted(node.func).endswith('.connect') and any(k.arg == 'check_same_thread' and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                assumption(file, node, 'SQLite connection is assumed safe across threads', 'Use a connection per worker or serialize every transaction and test concurrent writes')
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[f"{module}.{node.name}"] = (file, node)
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions[f"{module}.{node.name}.{method.name}"] = (file, method)
    def resolve(file, name):
        head, sep, rest = name.partition('.')
        mapped = aliases[file].get(head, head) + (sep + rest if sep else '')
        local = modules[file] + '.' + mapped
        if local in functions:
            return local
        if mapped in functions:
            return mapped
        # Sibling bare imports inside a package.
        prefix = modules[file].rpartition('.')[0]
        sibling = prefix + '.' + mapped if prefix else mapped
        return sibling if sibling in functions else mapped
    summaries = {name: set() for name in functions}
    return_taint = {name: set() for name in functions}
    for _round in range(len(functions) + 1):
        changed = False
        for name, (file, fn) in functions.items():
            params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
            env = {a.arg: {i} for i, a in enumerate(params)}
            instances = {'self': name.rsplit('.', 1)[0]}
            for item in ast.walk(fn):
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call):
                    constructor = resolve(file, dotted(item.value.func))
                    local_constructor = modules[file] + '.' + constructor
                    if any(f.startswith(local_constructor + '.') for f in functions):
                        constructor = local_constructor
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            instances[target.id] = constructor
            def resolve_call(node):
                raw = dotted(node.func)
                head, dot, tail = raw.partition('.')
                return instances[head] + dot + tail if dot and head in instances else resolve(file, raw)
            def call_args(node, callee):
                args = {i: a for i, a in enumerate(node.args)}
                if callee in functions:
                    callee_args = functions[callee][1].args
                    names = [a.arg for a in callee_args.posonlyargs + callee_args.args + callee_args.kwonlyargs]
                    if names and names[0] in ('self', 'cls') and '.' in dotted(node.func):
                        args = {i+1: a for i, a in args.items()}
                    args.update({names.index(k.arg): k.value for k in node.keywords if k.arg in names})
                return args
            for decorator in fn.decorator_list:
                dec = resolve(file, dotted(decorator.func if isinstance(decorator, ast.Call) else decorator))
                edge = {'caller': name, 'callee': dec, 'file': file, 'line': decorator.lineno, 'resolved': dec in functions, 'kind': 'decorator'}
                if edge not in edges:
                    edges.append(edge)
                assumption(file, decorator, 'Decorator is assumed to sanitize or preserve arguments', 'Verify the decorator wrapper and every alternate entry point; enforce validation at the sink')
            def taint(node):
                if node is None:
                    return set()
                if isinstance(node, ast.Name):
                    return env.get(node.id, set())
                if isinstance(node, ast.Call):
                    callee = resolve_call(node)
                    if callee in ('input', 'os.getenv', 'os.environ.get') or callee.startswith(('request.', 'flask.request.')):
                        return {-1}
                    if callee in return_taint:
                        args = call_args(node, callee)
                        return ({-1} if -1 in return_taint[callee] else set()) | set().union(*(taint(a) for i, a in args.items() if i in return_taint[callee]))
                if isinstance(node, ast.Subscript) and dotted(node.value) in ('os.environ', 'request.args', 'request.form', 'request.json'):
                    return {-1}
                return set().union(*(taint(c) for c in ast.iter_child_nodes(node)))
            fn_summary, returns = set(summaries[name]), set(return_taint[name])
            # AST order propagates assignment aliases; repeated function rounds
            # propagate caller/callee summaries to a fixed point (including cycles).
            nodes = list(ast.walk(fn))
            nodes.sort(key=lambda n: (getattr(n, 'lineno', 0), getattr(n, 'col_offset', 0)))
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = taint(node.value)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            env[target.id] = env.get(target.id, set()) | value
                if isinstance(node, ast.Return):
                    returns |= taint(node.value)
                if not isinstance(node, ast.Call):
                    continue
                call = resolve_call(node)
                edge = {"caller": name, "callee": call, "file": file, "line": node.lineno,
                        "resolved": call in functions}
                if edge not in edges:
                    edges.append(edge)
                rule = None
                if call not in functions and call.endswith((".execute", ".executemany", ".executescript")) and node.args and taint(node.args[0]):
                    rule = "CWE-89"
                shell = any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
                if call in {"os.system", "os.popen"} or (call.startswith("subprocess.") and shell):
                    if node.args and taint(node.args[0]):
                        rule = "CWE-78"
                if call.startswith("random.") and any(x in fn.name.lower() for x in ("token", "secret", "otp", "password", "nonce")):
                    finding("CWE-338", file, node, "Security material uses non-cryptographic random")
                if rule:
                    for idx in taint(node.args[0]):
                        fn_summary.add((idx, rule))
                    finding(rule, file, node, f"Parameter reaches {call} without a binding/argv boundary", [name, call])
                    assumption(file, node, 'Upstream caller is assumed to sanitize data', 'Enforce SQL parameter binding or argv separation inside the sink; exercise hostile inputs through every caller')
                if call in summaries:
                    args = call_args(node, call)
                    for idx, sink_rule in summaries[call]:
                        incoming = {-1} if idx == -1 else taint(args.get(idx))
                        if incoming:
                            fn_summary |= {(i, sink_rule) for i in incoming}
                            finding(sink_rule, file, node, f"Cross-file taint reaches {call}", [name, call])
            if fn_summary != summaries[name] or returns != return_taint[name]:
                summaries[name], return_taint[name] = fn_summary, returns
                changed = True
        if not changed:
            break
    # Concurrency analysis is conservative and explicitly surfaced for review.
    blocking = {"time.sleep", "requests.get", "requests.post", "urllib.request.urlopen", "open",
                "subprocess.run", "subprocess.call", "subprocess.check_output", "os.system", "sqlite3.connect"}
    blocking_functions = set()
    for name, (file, fn) in functions.items():
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        if any(resolve(file, dotted(n.func)) in blocking for n in calls):
            blocking_functions.add(name)
        checks = [n for n in calls if dotted(n.func).endswith((".exists", ".is_file", ".isfile", ".access", ".resolve"))]
        uses = [n for n in calls if dotted(n.func) == 'open' or dotted(n.func).endswith((".open", ".unlink", ".remove", ".read_text", ".write_text"))]
        if checks and uses and any(u.lineno > c.lineno for u in uses for c in checks):
            finding("CWE-367", file, uses[0], "Path check followed by file use; require atomic descriptor access or review symlink races")
        queries = [ast.unparse(n).upper() for n in calls if dotted(n.func).endswith(".execute")]
        if any('SELECT' in q for q in queries) and any('UPDATE' in q or 'INSERT' in q for q in queries):
            if not any('BEGIN IMMEDIATE' in q or 'FOR UPDATE' in q for q in queries):
                finding("CWE-362", file, fn, "Database check then mutation needs transactional concurrency review")
        globals_ = {s for n in ast.walk(fn) if isinstance(n, ast.Global) for s in n.names}
        global_updates = [n for n in ast.walk(fn) if isinstance(n, ast.AugAssign)
                          and isinstance(n.target, ast.Name) and n.target.id in globals_]
        lock_nodes = [n for n in ast.walk(fn) if isinstance(n, (ast.With, ast.AsyncWith))
                      and any('lock' in ast.unparse(i.context_expr).lower() for i in n.items)]
        if global_updates and not lock_nodes:
            finding('CWE-362', file, global_updates[0], 'Shared read-modify-write state requires lock or atomic operation review')
        if isinstance(fn, ast.AsyncFunctionDef) and any(isinstance(n, ast.Await) for n in ast.walk(fn)):
            writes = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AugAssign))]
            if globals_ and writes and not lock_nodes:
                finding('CWE-362', file, fn, 'Shared state mutation across await without an async lock')
    for _ in functions:
        newly = {e['caller'] for e in edges if e['callee'] in blocking_functions}
        if newly <= blocking_functions:
            break
        blocking_functions |= newly
    for name in sorted(blocking_functions):
        file, fn = functions[name]
        if isinstance(fn, ast.AsyncFunctionDef):
            finding("ASYNC-BLOCKING", file, fn, "Synchronous blocking I/O is reachable from async code; offload or use async APIs")
    # Expand diagnostic paths beyond one edge without executing target modules.
    for item in findings:
        if not item.get('flow'):
            continue
        first = item['flow'][0]
        queue = deque([(first, [first])])
        visited = set()
        while queue:
            current, path = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            direct = next((f for f in findings if f['rule_id'] == item['rule_id'] and f.get('flow', [None])[0] == current and 'without a binding' in f['reason']), None)
            if direct:
                item['flow'] = path + [direct['flow'][-1]]
                break
            for edge in edges:
                if edge['caller'] == current and edge['callee'] not in visited:
                    queue.append((edge['callee'], path + [edge['callee']]))
    return {"assumptions": sorted(assumptions, key=lambda a: (a['file'], a['line'])), "files_scanned": len(sources), "functions": sorted(functions),
            "edges": sorted(edges, key=lambda e: (e['file'], e['line'], e['callee'])),
            "findings": sorted(findings, key=lambda f: (f['file'], f['line'], f['rule_id'])),
            "coverage_limits": limits + ["Dynamic dispatch, reflection and external dependencies require model/runtime review"]}


def patch_context(target_file, original, patched=None):
    path = Path(target_file).resolve()
    root = path.parent.parent if path.parent.name == 'benchmark_targets' else path.parent
    rel = str(path.relative_to(root))
    sources, limits = collect_sources(root)
    sources[rel] = original
    before = analyze_sources(sources)
    after = analyze_sources({**sources, rel: patched}) if patched is not None else before
    old = {(f['file'], f['rule_id'], f['reason']) for f in before['findings']}
    introduced = [f for f in after['findings'] if (f['file'], f['rule_id'], f['reason']) not in old]
    # Only include bounded source context; no silent truncation of the target.
    related = {rel}
    # Shared external APIs (logging, sqlite3.connect, json.dumps, ...) do not
    # connect otherwise unrelated application modules. Traverse resolved local
    # function edges in both directions, preserving real callers and helpers.
    context_edges = [e for e in before['edges'] + after['edges'] if e['resolved']]
    module = rel.removesuffix('.py').replace('/', '.').removesuffix('.__init__')
    queue = deque(name for name in set(before['functions'] + after['functions']) if name.startswith(module + '.'))
    visited = set()
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        for e in context_edges:
            if e['caller'] == current or e['callee'] == current:
                related.add(e['file'])
                queue.extend(x for x in (e['caller'], e['callee']) if x not in visited)
    for file, module in ((f, f.removesuffix('.py').replace('/', '.')) for f in sources):
        if any(name.startswith(module + '.') for name in visited):
            related.add(file)
    return {"target": rel, "sources": {f: sources[f] for f in sorted(related)},
            "before": before, "after": after, "introduced": introduced,
            "coverage_limits": limits + after['coverage_limits']}

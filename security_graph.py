"""Bounded static call graph and conservative interprocedural taint/concurrency audit.

No target imports are executed. Unresolved/dynamic calls are recorded as coverage
limits; this analysis supplements model review and sandbox evidence, not proof.
"""
import ast
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
    candidates = sorted(p for p in root.rglob("*.py") if not any(x in EXCLUDED for x in p.relative_to(root).parts))
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
            def taint(node):
                if node is None:
                    return set()
                if isinstance(node, ast.Name):
                    return env.get(node.id, set())
                if isinstance(node, ast.Call):
                    callee = resolve(file, dotted(node.func))
                    if callee in return_taint:
                        return set().union(*(taint(a) for i, a in enumerate(node.args) if i in return_taint[callee]))
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
                call = resolve(file, dotted(node.func))
                edge = {"caller": name, "callee": call, "file": file, "line": node.lineno,
                        "resolved": call in functions}
                if edge not in edges:
                    edges.append(edge)
                rule = None
                if call.endswith((".execute", ".executemany", ".executescript")) and node.args and taint(node.args[0]):
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
                if call in summaries:
                    callee_params = functions[call][1].args
                    param_names = [a.arg for a in callee_params.posonlyargs + callee_params.args + callee_params.kwonlyargs]
                    args = {i: a for i, a in enumerate(node.args)}
                    args.update({param_names.index(k.arg): k.value for k in node.keywords if k.arg in param_names})
                    for idx, sink_rule in summaries[call]:
                        incoming = taint(args.get(idx))
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
    return {"files_scanned": len(sources), "functions": sorted(functions),
            "edges": sorted(edges, key=lambda e: (e['file'], e['line'], e['callee'])),
            "findings": sorted(findings, key=lambda f: (f['file'], f['line'], f['rule_id'])),
            "coverage_limits": limits + ["Dynamic dispatch, reflection and external dependencies require model/runtime review"]}


def patch_context(target_file, original, patched=None):
    path = Path(target_file).resolve()
    root = path.parent
    if root.name != 'benchmark_targets' and (root / 'benchmark_targets').is_dir():
        root = path.parent
    rel = str(path.relative_to(root))
    sources, limits = collect_sources(root / 'benchmark_targets') if (root / 'benchmark_targets').is_dir() else collect_sources(root)
    if (root / 'benchmark_targets').is_dir():
        sources = {'benchmark_targets/' + k: v for k, v in sources.items()}
    sources[rel] = original
    before = analyze_sources(sources)
    after = analyze_sources({**sources, rel: patched}) if patched is not None else before
    old = {(f['file'], f['rule_id'], f['reason']) for f in before['findings']}
    introduced = [f for f in after['findings'] if (f['file'], f['rule_id'], f['reason']) not in old]
    # Only include bounded source context; no silent truncation of the target.
    related = {rel}
    context_edges = before['edges'] + after['edges']
    queue = deque([e['caller'] for e in context_edges if e['file'] == rel])
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

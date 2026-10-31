"""Non-executing JavaScript/TypeScript parsing and bounded security analysis."""
import base64
import json
from pathlib import Path
import re

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

GRAMMARS = {'javascript': Language(tree_sitter_javascript.language()),
            'typescript': Language(tree_sitter_typescript.language_typescript())}


def text(node):
    return node.text.decode() if node else ''


def walk(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def parse(code, language='javascript'):
    encoded = code.encode()
    if len(encoded) > 800_000:
        raise ValueError('Source exceeds parser size limit')
    tree = Parser(GRAMMARS[language]).parse(encoded)
    if tree.root_node.has_error:
        raise SyntaxError(f'Invalid {language} syntax')
    return tree.root_node


def literal(node):
    if not node or node.type not in ('string', 'template_string'):
        return None
    if any(n.type == 'template_substitution' for n in walk(node)):
        return None
    raw = text(node)
    # Static literal recognition is deliberately conservative; no eval/unescape.
    return raw[1:-1] if len(raw) >= 2 and '\\' not in raw else None


def sanitize(code, language):
    from ingress_sanitizer import _hostile
    try:
        root = parse(code, language)
    except (SyntaxError, ValueError):
        return {'content': code, 'valid': False, 'sanitized_count': 0}
    edits = []
    for node in walk(root):
        if node.type not in ('comment', 'string', 'template_string'):
            continue
        raw = text(node)
        hostile = _hostile(raw)
        value = literal(node)
        if not hostile and value and len(value) >= 40:
            try:
                hostile = _hostile(base64.b64decode(value, validate=True).decode())
            except (ValueError, UnicodeError):
                pass
        if not hostile:
            continue
        if node.type == 'template_string' and value is None:
            return {'content': code, 'valid': False, 'sanitized_count': 0}
        replacement = ''.join('\n' if c == '\n' else ' ' for c in raw) if node.type == 'comment' else json.dumps('[AgentWard: instruction removed]')
        edits.append((node.start_byte, node.end_byte, replacement.encode()))
    data = code.encode()
    for start, end, replacement in sorted(edits, reverse=True):
        data = data[:start] + replacement + data[end:]
    result = data.decode()
    try:
        parse(result, language)
        valid = True
    except SyntaxError:
        valid = False
    return {'content': result, 'valid': valid, 'sanitized_count': len(edits)}


FUNCTION_TYPES = {'function_declaration', 'function_expression', 'arrow_function', 'generator_function_declaration'}


def inventory(code, language):
    root = parse(code, language)
    functions, exports, imports = {}, {}, []
    for item in root.named_children:
        node = item.child_by_field_name('declaration') if item.type == 'export_statement' else item
        if node is None:
            node = item
        if node.type in FUNCTION_TYPES:
            name = text(node.child_by_field_name('name'))
            if name:
                functions[name] = node
                if item.type == 'export_statement':
                    exports['default' if any(c.type == 'default' for c in item.children) else name] = name
        if node.type in ('lexical_declaration', 'variable_declaration'):
            for decl in node.named_children:
                name, value = text(decl.child_by_field_name('name')), decl.child_by_field_name('value')
                if value and value.type in FUNCTION_TYPES:
                    functions[name] = value
                    if item.type == 'export_statement':
                        exports[name] = name
        if item.type == 'export_statement':
            for clause in item.named_children:
                if clause.type == 'export_clause':
                    for spec in clause.named_children:
                        name = text(spec.child_by_field_name('name'))
                        exports[text(spec.child_by_field_name('alias')) or name] = name
        if node.type == 'expression_statement' and node.named_children:
            assignment = node.named_children[0]
            if assignment.type == 'assignment_expression':
                left, right = text(assignment.child_by_field_name('left')), assignment.child_by_field_name('right')
                if left == 'module.exports' and right.type == 'object':
                    for prop in right.named_children:
                        if prop.type == 'shorthand_property_identifier':
                            exports[text(prop)] = text(prop)
                        elif prop.type == 'pair':
                            exports[text(prop.child_by_field_name('key'))] = text(prop.child_by_field_name('value'))
                elif left.startswith(('exports.', 'module.exports.')):
                    name = left.split('.')[-1]
                    if right.type in FUNCTION_TYPES:
                        functions[name] = right
                        exports[name] = name
                    else:
                        exports[name] = text(right)
        for child in walk(item):
            if child.type == 'import_statement':
                imports.append(literal(child.child_by_field_name('source')))
            if child.type == 'call_expression' and text(child.child_by_field_name('function')) in ('require', 'import'):
                args = child.child_by_field_name('arguments')
                imports.append(literal(args.named_children[0]) if args and args.named_children else None)
    return root, functions, exports, imports


def parameters(fn):
    params = fn.child_by_field_name('parameters')
    if params is None:
        param = fn.child_by_field_name('parameter')
        return [text(param)] if param else []
    result = []
    for item in params.named_children:
        if item.type == 'identifier':
            result.append(text(item))
        elif item.type in ('required_parameter', 'optional_parameter'):
            pattern = item.child_by_field_name('pattern')
            if pattern and pattern.type == 'identifier':
                result.append(text(pattern))
            else:
                result.append(None)
        else:
            result.append(None)
    return result


def builtin_bindings(root):
    """Resolve static ES/CommonJS bindings without loading any module."""
    bindings = {}
    for node in walk(root):
        if node.type == 'import_statement':
            source = literal(node.child_by_field_name('source'))
            if source not in ('node:child_process', 'child_process'):
                continue
            for part in walk(node):
                if part.type == 'import_specifier':
                    name = text(part.child_by_field_name('name'))
                    bindings[text(part.child_by_field_name('alias')) or name] = 'child_process.' + name
                elif part.type == 'namespace_import':
                    bindings[text(part.named_children[-1])] = 'child_process'
                elif part.type == 'import_clause':
                    for item in part.named_children:
                        if item.type == 'identifier':
                            bindings[text(item)] = 'child_process'
        if node.type != 'variable_declarator':
            continue
        name, value = node.child_by_field_name('name'), node.child_by_field_name('value')
        if value is None or value.type != 'call_expression' or text(value.child_by_field_name('function')) != 'require':
            continue
        args = value.child_by_field_name('arguments').named_children
        if not args or literal(args[0]) not in ('node:child_process', 'child_process'):
            continue
        if name.type == 'identifier':
            bindings[text(name)] = 'child_process'
        elif name.type == 'object_pattern':
            for item in name.named_children:
                if item.type == 'shorthand_property_identifier_pattern':
                    bindings[text(item)] = 'child_process.' + text(item)
                elif item.type == 'pair_pattern':
                    bindings[text(item.child_by_field_name('value'))] = 'child_process.' + text(item.child_by_field_name('key'))
    return bindings


def resolved_call(node, bindings):
    name = text(node.child_by_field_name('function'))
    prefix, dot, suffix = name.partition('.')
    return bindings.get(prefix, prefix) + (dot + suffix if dot else '')


def normalized(node):
    if node is None:
        return ''
    if not node.children:
        return (node.type, text(node))
    return (node.type, tuple(normalized(c) for c in node.children if c.type != 'comment'))


def public_signatures(code, language):
    _, functions, exports, _ = inventory(code, language)
    result = {}
    for public, local in exports.items():
        fn = functions.get(local)
        if fn is None:
            result[public] = ('unresolved', local)
            continue
        result[public] = (any(c.type == 'async' for c in fn.children),
                          any(c.type == '*' for c in fn.children),
                          normalized(fn.child_by_field_name('parameters') or fn.child_by_field_name('parameter')),
                          normalized(fn.child_by_field_name('return_type')))
    return result


def detect_tripwire(code, language):
    root, functions, exports, _ = inventory(code, language)
    decoys, helpers, guards = {}, set(), []
    for item in root.named_children:
        node = item.child_by_field_name('declaration') if item.type == 'export_statement' else item
        if node is not None and node.type in ('lexical_declaration', 'variable_declaration'):
            for decl in node.named_children:
                name = text(decl.child_by_field_name('name'))
                value = literal(decl.child_by_field_name('value'))
                if re.search(r'_(DECOY|LEGACY|HONEY|CANARY)$', name) and value and len(value) >= 16:
                    decoys[name] = value
    for name, fn in functions.items():
        for node in walk(fn.child_by_field_name('body')):
            if node.type == 'call_expression' and text(node.child_by_field_name('function')) in ('console.warn', 'console.error'):
                args = node.child_by_field_name('arguments').named_children
                if args and 'TRIPWIRE' in (literal(args[0]) or ''):
                    helpers.add(name)
    for public, local in exports.items():
        fn = functions.get(local)
        if fn is None:
            continue
        params = parameters(fn)
        for node in walk(fn.child_by_field_name('body')):
            if node.type != 'if_statement':
                continue
            condition = node.child_by_field_name('condition')
            if condition and condition.type == 'parenthesized_expression':
                condition = condition.named_children[0]
            if condition is None or condition.type != 'binary_expression' or not any(c.type == '===' for c in condition.children):
                continue
            operands = {text(condition.child_by_field_name('left')), text(condition.child_by_field_name('right'))}
            calls = [text(n.child_by_field_name('function')) for n in walk(node.child_by_field_name('consequence')) if n.type == 'call_expression']
            for decoy in operands & decoys.keys():
                for param in operands & set(params):
                    if helpers.intersection(calls):
                        guards.append({'function': public, 'parameter': param, 'parameter_index': params.index(param),
                                       'decoy': decoy, 'value': decoys[decoy], 'line': node.start_point.row + 1})
    return {'present': bool(guards), 'has_logger': bool(helpers), 'markers': sorted(decoys.keys() | helpers), 'guards': guards}


def analyze_sources(sources):
    findings, edges, names, limits = [], [], [], []
    for file, code in sorted(sources.items()):
        language = 'typescript' if Path(file).suffix in ('.ts', '.mts', '.cts') else 'javascript'
        try:
            root, functions, exports, imports = inventory(code, language)
        except (SyntaxError, ValueError):
            limits.append(f'Invalid ECMAScript syntax in {file}')
            continue
        for imported in imports:
            if imported is None or not imported.startswith('node:'):
                limits.append(f'{file}: dependency {imported!r} requires separate runtime coverage')
        module = str(Path(file).with_suffix('')).replace('/', '.')
        bindings = builtin_bindings(root)
        for name, fn in functions.items():
            full = module + '.' + name
            names.append(full)
            tainted = {p for p in parameters(fn) if p}
            nodes = list(walk(fn.child_by_field_name('body')))
            def contains_taint(node):
                return node is not None and any(n.type == 'identifier' and text(n) in tainted for n in walk(node))
            for _ in range(8):
                previous = set(tainted)
                for n in nodes:
                    if n.type == 'variable_declarator' and contains_taint(n.child_by_field_name('value')):
                        tainted.add(text(n.child_by_field_name('name')))
                    if n.type == 'assignment_expression' and contains_taint(n.child_by_field_name('right')):
                        tainted.add(text(n.child_by_field_name('left')))
                if tainted == previous:
                    break
            for node in nodes:
                if node.type != 'call_expression':
                    continue
                call = resolved_call(node, bindings)
                args = node.child_by_field_name('arguments').named_children
                edges.append({'file': file, 'line': node.start_point.row + 1, 'caller': full,
                              'callee': module + '.' + call if call in functions else call, 'resolved': call in functions})
                rule = None
                # Shell-taking APIs remain conservative even through aliases.
                if call in ('child_process.exec', 'child_process.execSync') and args and contains_taint(args[0]):
                    rule = 'CWE-78'
                if re.search(r'\b(prepare|query|execute)$', call) and args and contains_taint(args[0]):
                    rule = 'CWE-89'
                if call == 'Math.random' and re.search(r'token|secret|nonce|password|otp', name, re.I):
                    rule = 'CWE-338'
                if call in ('eval', 'Function', 'vm.runInNewContext', 'vm.runInThisContext'):
                    rule = 'CWE-95'
                if rule:
                    findings.append({'rule_id': rule, 'file': file, 'line': node.start_point.row + 1,
                                     'reason': 'Untrusted parameter reaches ' + call if rule != 'CWE-338' else 'Security value uses Math.random',
                                     'severity': 'SUSPICIOUS', 'flow': [full, call]})
    return {'files_scanned': len(sources), 'functions': sorted(names), 'edges': edges,
            'findings': findings, 'assumptions': [], 'coverage_limits': limits + [
                'ECMAScript taint is intraprocedural; import aliases, dynamic dispatch, closures and cross-file propagation require independent review.',
                'Node probes cover named exported SQL/command functions; external packages, browser/JSX, project builds and TypeScript type checking are outside this adapter.']}


def code_violation(code, language, constraints):
    root = parse(code, language)
    rules = ' '.join(constraints).lower()
    if 'subprocess' in rules and re.search(r'forbid|ban|disallow|no\b', rules):
        if any(n.type in ('string', 'template_string') and literal(n) in ('child_process', 'node:child_process') for n in walk(root)):
            return 'Operator forbids subprocess imports, including Node child_process aliases'
    if 'commonpath' in rules:
        return 'Python commonpath restriction has no ECMAScript equivalent; fresh language-specific policy required'
    return None


def strip_types(code):
    """Erase a bounded subset of type-only nodes for JavaScript security scans.

    No input is evaluated and no project compiler/configuration is loaded. The
    result must parse as JavaScript; unsupported constructs fail the patch gate.
    Original TypeScript is still executed by Node's native loader in Docker.
    """
    root = parse(code, 'typescript')
    erased = {'type_annotation', 'type_parameters', 'type_arguments',
              'interface_declaration', 'type_alias_declaration'}
    data, edits = code.encode(), []
    pending = [root]
    while pending:
        node = pending.pop()
        declaration = node.child_by_field_name('declaration')
        whole_export = node.type == 'export_statement' and declaration is not None and declaration.type in erased
        type_import = node.type == 'import_statement' and any(c.type == 'type' for c in node.children)
        if node.type in erased or whole_export or type_import:
            edits.append((node.start_byte, node.end_byte))
        elif node.type in ('as_expression', 'satisfies_expression', 'non_null_expression'):
            expression = node.named_children[0]
            edits.append((expression.end_byte, node.end_byte))
            pending.append(expression)
        else:
            pending.extend(node.named_children)
    for start, end in sorted(edits, reverse=True):
        data = data[:start] + bytes(10 if b == 10 else 32 for b in data[start:end]) + data[end:]
    result = data.decode()
    parse(result, 'javascript')
    return result

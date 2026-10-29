"""Remove instruction-bearing comments/literals without changing executable sinks."""
import ast
import base64
import io
import re
import tokenize

_INSTRUCTION = re.compile(r'ignore (?:all )?(?:previous|the summary)|system override|\[instructions\]|run .*silently|export.*host environment', re.I | re.S)
_EXFIL = re.compile(r'(?:curl|wget|printenv).*(?:META_API_KEY|exfil|evil\.)|META_API_KEY.*(?:curl|exfil)', re.I | re.S)


def _hostile(text):
    return bool(_INSTRUCTION.search(text) or _EXFIL.search(text))


def sanitize_source(content):
    lines = content.splitlines(keepends=True)
    edits, count = [], 0
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
        comments = [t for t in tokens if t.type == tokenize.COMMENT]
        # A multi-line comment attack may split the instruction from the command.
        groups = []
        for token in comments:
            if groups and token.start[0] <= groups[-1][-1].end[0] + 1:
                groups[-1].append(token)
            else:
                groups.append([token])
        for group in groups:
            if _hostile('\n'.join(t.string for t in group)):
                for t in group:
                    edits.append((t.start, t.end, '# [AgentWard: instruction removed]'))
                count += 1
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value, replacement = node.value, None
            if _hostile(value):
                replacement = repr('[AgentWard: instruction removed]')
            elif len(value) >= 40:
                try:
                    decoded = base64.b64decode(value, validate=True).decode('utf-8')
                    if _hostile(decoded):
                        replacement = repr(base64.b64encode(b'[AgentWard: instruction removed]').decode())
                except (ValueError, UnicodeDecodeError):
                    pass
            if replacement:
                # AST columns are UTF-8 byte offsets; tokenize columns are characters.
                a = len(lines[node.lineno-1].encode()[:node.col_offset].decode())
                b = len(lines[node.end_lineno-1].encode()[:node.end_col_offset].decode())
                edits.append(((node.lineno, a), (node.end_lineno, b), replacement))
                count += 1
    except (SyntaxError, tokenize.TokenError):
        return {'content': content, 'sanitized_count': 0, 'valid': False}
    offsets, total = [], 0
    for line in lines:
        offsets.append(total)
        total += len(line)
    for start, end, replacement in sorted(edits, reverse=True):
        a, b = offsets[start[0]-1]+start[1], offsets[end[0]-1]+end[1]
        content = content[:a] + replacement + content[b:]
    try:
        ast.parse(content)
        valid = True
    except SyntaxError:
        valid = False
    return {'content': content, 'sanitized_count': count, 'valid': valid}

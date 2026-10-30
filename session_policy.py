"""Append-only operator policy shared by every run in one dashboard session."""
import ast
import re

BYPASS = re.compile(r'(?:bypass|disable|skip|ignore|waive).{0,60}(?:guard|review|consensus|codeshield|sandbox|gate)|(?:printenv|/proc/self/environ|os\.environ|\.env\b)', re.I)


class SessionPolicy:
    def __init__(self):
        self.revision = 0
        self.constraints = []
        self.guards = set()
        self.halted = False

    def snapshot(self):
        return {'revision': self.revision, 'constraints': list(self.constraints), 'halted': self.halted}

    def tighten(self, constraint):
        constraint = constraint.strip()
        if not 1 <= len(constraint) <= 2000:
            raise ValueError('Constraint must contain 1–2000 characters')
        if len(self.constraints) >= 32:
            raise ValueError('Session constraint limit reached')
        if BYPASS.search(constraint) or re.search(r'\b(?:allow|permit|relax|remove|override)\b', constraint, re.I):
            raise ValueError('Steering may only add restrictions; mandatory gates cannot be relaxed')
        self.constraints.append(constraint)
        self.revision += 1
        return self.snapshot()

    def action_violation(self, action):
        if self.halted:
            return 'Session halted by misalignment monitor'
        if BYPASS.search(action):
            return 'Auto-review bypass or environment probing'
        if any('subprocess' in c.lower() and re.search(r'forbid|ban|disallow|no\b', c, re.I) for c in self.constraints):
            if re.search(r'subprocess|os\.system|os\.popen|shell\s*=\s*true', action, re.I):
                return 'Operator forbids subprocess calls'
        return None

    def code_violation(self, code):
        # AST enforcement avoids a comment falsely satisfying a new constraint.
        if self.halted:
            return 'Session halted by misalignment monitor'
        tree = ast.parse(code)
        calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
        rules = ' '.join(self.constraints).lower()
        if 'subprocess' in rules and re.search(r'forbid|ban|disallow|no\b', rules):
            if any(c.startswith('subprocess.') or c in ('os.system', 'os.popen') for c in calls):
                return 'Operator forbids subprocess calls'
            if any(isinstance(n, (ast.Import, ast.ImportFrom)) and 'subprocess' in ast.unparse(n) for n in ast.walk(tree)):
                return 'Operator forbids subprocess imports, including aliases'
        if 'commonpath' in rules:
            uses_paths = any(c in ('open', 'os.remove', 'os.unlink') or c.endswith(('.open', '.read_text', '.write_text', '.unlink')) for c in calls)
            if uses_paths and not any(c.endswith(('.commonpath', '.is_relative_to', '.relative_to')) for c in calls):
                return 'Operator requires component-aware path containment'
        return None

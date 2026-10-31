"""Explicit source-language registry; filenames never select arbitrary commands."""
from dataclasses import dataclass
from pathlib import Path
import ast


class UnsupportedLanguage(ValueError):
    code = 'UNSUPPORTED_LANGUAGE'


@dataclass(frozen=True)
class LanguageAdapter:
    name: str
    extensions: tuple[str, ...]
    harness_filename: str
    runtime: str

    def parse(self, code):
        if self.name == 'python':
            return ast.parse(code)
        from ecmascript import parse
        return parse(code, self.name)

    def sanitize(self, code):
        if self.name == 'python':
            from ingress_sanitizer import sanitize_source
            return sanitize_source(code)
        from ecmascript import sanitize
        return sanitize(code, self.name)

    def public_signatures(self, code):
        if self.name == 'python':
            from museverify_stage4 import public_signatures
            return public_signatures(code)
        from ecmascript import public_signatures
        return public_signatures(code, self.name)

    def tripwire(self, code):
        if self.name == 'python':
            from museverify_stage4 import detect_tripwire
            return detect_tripwire(code)
        from ecmascript import detect_tripwire
        return detect_tripwire(code, self.name)


ADAPTERS = (
    LanguageAdapter('python', ('.py',), 'verify_test.py', 'python3'),
    LanguageAdapter('javascript', ('.js', '.mjs', '.cjs'), 'verify_test.mjs', 'node'),
    LanguageAdapter('typescript', ('.ts', '.mts', '.cts'), 'verify_test.mjs', 'node'),
)
SUPPORTED_EXTENSIONS = frozenset(ext for a in ADAPTERS for ext in a.extensions)


def adapter_for(filename):
    suffix = Path(filename).suffix.lower()
    for adapter in ADAPTERS:
        if suffix in adapter.extensions:
            return adapter
    raise UnsupportedLanguage(f'Unsupported source extension: {suffix or "(none)"}')


def language_capabilities():
    return [{'language': a.name, 'extensions': list(a.extensions), 'runtime': a.runtime,
             'scope': 'Python benchmark probes' if a.name == 'python' else
             'Single-file Node.js modules; exported functions; SQL/command probes; built-in dependencies only'}
            for a in ADAPTERS]

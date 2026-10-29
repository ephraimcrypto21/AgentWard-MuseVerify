"""Deterministic model responses for offline tests; never used by production routes."""
from pathlib import Path
import json
from ingress_sanitizer import sanitize_source

ROOT = Path(__file__).resolve().parents[1]


def patch_for(target):
    code = sanitize_source((ROOT / target).read_text())['content']
    if target == 'poisoned_app.py':
        code = code.replace('query = f"SELECT * FROM users WHERE username = \'{username}\'"', 'query = "SELECT * FROM users WHERE username = ?"')
        code = code.replace('cursor.execute(query)', 'cursor.execute(query, (username,))')
        func, arg = 'get_user', 'username'
    elif target.endswith('cwe_89_sqli.py'):
        code = code.replace('query = f"SELECT id, name, sku FROM products WHERE name LIKE \'%{name_fragment}%\'"', 'query = "SELECT id, name, sku FROM products WHERE name LIKE ?"')
        code = code.replace('cursor.execute(query)', 'cursor.execute(query, ("%" + name_fragment + "%",))')
        func, arg = 'search_products', 'name_fragment'
    else:
        raise ValueError(target)
    # Add guard immediately after signature. Normal calls never log.
    needle = f'def {func}({arg}):\n'
    code = code.replace(needle, needle + f'    if {arg} == INPUT_DECOY:\n        _tripwire()\n')
    code += '''
import logging
INPUT_DECOY = "agentward-fake-canary-71edc90a"
def _tripwire():
    logging.getLogger(__name__).warning("TRIPWIRE legacy input observed")
'''
    return code


async def fake_query(prompt, system_prompt='', provider=None, model=None, **kwargs):
    task = kwargs.get('task', 'policy_check')
    if task == 'patch_synthesis':
        target = 'benchmark_targets/cwe_89_sqli.py' if 'search_products' in prompt.split('IMPORT/CALL GRAPH')[0] else 'poisoned_app.py'
        return patch_for(target)
    if task == 'patch_verification':
        return json.dumps({'approve': True, 'fixes_vulnerability': True, 'introduces_new_risk': False, 'reason': 'Deterministic test fixture reviewer'})
    if task == 'selfplay':
        # Mutations for all column counts; valid baseline controls distinguish them.
        return json.dumps({'sqli': ["'/**/UNION/**/SELECT/**/'AGENTWARD_SQLI',1,1/**/--", "'/**/UNION/**/SELECT/**/1,'AGENTWARD_SQLI'/**/--"],
                           'cmd': ['127.0.0.1&&echo AGENTWARD_CMD>__MARKER__']})
    if task == 'semantic_hunt':
        if 'taxonomist' in system_prompt:
            return json.dumps({'family': 'sqli', 'root_cause': 'Untrusted input interpolated into SQL', 'semantic_signature': 'source to SQL', 'indicators': ['execute']})
        return '{"matches": []}'
    if 'contains_secret_leak' in system_prompt:
        return '{"contains_secret_leak": false, "risk": "low", "reason": "Fixture safe action"}'
    return '{"approve": true, "risk": "low", "reason": "Fixture safe action"}'

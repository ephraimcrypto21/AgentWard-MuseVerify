#!/usr/bin/env python3
"""Prompt-Guard ingress with syntax-preserving local fallback."""
import json
import os
from pathlib import Path
import sys
import urllib.request
from dotenv import load_dotenv
from ingress_sanitizer import sanitize_source

load_dotenv()
PROMPT_GUARD_URL = os.getenv('AGENTWARD_INGRESS_URL', 'http://100.67.189.89:8000/scan-ingress')
LIGHTSAIL_SANDBOX_URL = os.getenv('AGENTWARD_SANDBOX_URL', 'http://100.67.189.89:8001/execute')


def check_prompt_guard(file_path, content):
    local = sanitize_source(content)
    data = {}
    if os.getenv('AGENTWARD_FORCE_LOCAL') != '1':
        request = urllib.request.Request(PROMPT_GUARD_URL,
            data=json.dumps({'file_path': file_path, 'content': content, 'text': content}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                data = json.loads(response.read())
        except Exception:
            pass
    label = str(data.get('label', data.get('verdict', 'benign'))).lower()
    if local['sanitized_count']:
        label = 'injection'
    return {**data, 'label': label, 'scores': data.get('scores', {}),
            'sanitized_content': local['content'], 'sanitized_count': local['sanitized_count'],
            'valid': local['valid'], 'backend': 'prompt_guard' if data else 'local_heuristic'}


def inspect_file_before_muse(file_path):
    try:
        content = Path(file_path).read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        return {'status': 'ERROR', 'reason': str(exc), 'content': '', 'sanitized_count': 0}
    result = check_prompt_guard(file_path, content)
    blocked = result.get('blocked') or result['label'] in ('injection', 'jailbreak')
    if not result['valid'] or (blocked and not result['sanitized_count']):
        return {'status': 'BLOCKED', 'content': '', 'reason': 'Input could not be safely sanitized', 'sanitized_count': 0}
    return {'status': 'SANITIZED' if result['sanitized_count'] else 'ALLOW',
            'reason': 'Instruction payloads removed' if result['sanitized_count'] else 'No ingress instruction detected',
            'content': result['sanitized_content'], 'sanitized_count': result['sanitized_count'], 'backend': result['backend']}


if __name__ == '__main__':
    print(json.dumps(inspect_file_before_muse(sys.argv[1] if len(sys.argv)>1 else 'poisoned_app.py'), indent=2))

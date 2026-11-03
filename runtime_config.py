"""Explicit project configuration for sandbox destinations and provider policy."""
import os
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from dotenv import dotenv_values, load_dotenv

DOTENV_PATH = Path(__file__).resolve().with_name('.env')
SANDBOX_ENDPOINTS = {'/health', '/execute', '/run-sandbox-test', '/run-poc-sandbox'}


def load_environment(*, override=False):
    """Load this project's file, never an unrelated working-directory .env."""
    load_dotenv(DOTENV_PATH, override=override, interpolate=False)


def sandbox_endpoint(endpoint):
    """Resolve a fixed service route from the current, required .env URL."""
    if endpoint not in SANDBOX_ENDPOINTS:
        raise ValueError('Unknown sandbox endpoint')
    url = (dotenv_values(DOTENV_PATH, interpolate=False).get('AGENTWARD_SANDBOX_URL') or '').strip()
    if not url:
        raise RuntimeError('AGENTWARD_SANDBOX_URL must be set in the project .env')
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme in {'http', 'https'} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and not (parsed.query or parsed.fragment)
                 and parsed.port != 0 and '\\' not in url
                 and not any(char.isspace() for char in url)
                 and parsed.path.rstrip('/') in {'', *SANDBOX_ENDPOINTS})
    except ValueError:
        valid = False
    if not valid:
        raise RuntimeError('AGENTWARD_SANDBOX_URL must be an HTTP(S) sandbox origin or known endpoint, without credentials, query or fragment')
    return urljoin(url.rstrip('/') + '/', endpoint)


def meta_only_required():
    """A file-level policy cannot be relaxed by an inherited shell or UI mode."""
    value = dotenv_values(DOTENV_PATH, interpolate=False).get(
        'AGENTWARD_META_ONLY', os.getenv('AGENTWARD_META_ONLY', '0'))
    if value not in {'0', '1'}:
        raise ValueError('AGENTWARD_META_ONLY must be 0 or 1')
    return value == '1'


load_environment()

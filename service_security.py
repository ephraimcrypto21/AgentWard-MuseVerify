"""Shared limits and authentication at the verification service boundary."""
import hmac
import os
import urllib.request
import urllib.error

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse

MAX_BODY_BYTES = 2_000_000


class BodyLimitMiddleware:
    """Bound even chunked bodies before JSON parsing or worker allocation."""

    def __init__(self, app, max_bytes=MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            body = message.get('body', b'')
            size += len(body)
            if size > self.max_bytes:
                return await JSONResponse({'detail': 'Request body too large'}, 413)(scope, receive, send)
            chunks.append(body)
            if not message.get('more_body', False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {'type': 'http.request', 'body': b''.join(chunks), 'more_body': False}

        await self.app(scope, replay, send)


def require_node_token(request: Request):
    token = os.getenv('AGENTWARD_NODE_TOKEN', '')
    if len(token) < 32:
        raise HTTPException(503, 'Node authentication is not configured')
    supplied = request.headers.get('authorization', '')
    if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
        raise HTTPException(401, 'Node authentication required', headers={'WWW-Authenticate': 'Bearer'})


def node_headers():
    headers = {'Content-Type': 'application/json'}
    token = os.getenv('AGENTWARD_NODE_TOKEN', '')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    return headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Node redirects are forbidden', headers, fp)


def node_urlopen(request, timeout):
    # Never forward service credentials to a redirect target or an ambient proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)

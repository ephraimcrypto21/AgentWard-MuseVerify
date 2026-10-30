"""Command center backed by the shared CLI pipeline and replayable run telemetry."""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
import itertools
import json
import logging
from pathlib import Path
import os

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from ai_provider import discover_and_verify_providers, configuration_update, select_ensemble, ProviderUnavailable
from session_policy import SessionPolicy
from reporting import executive_brief

from main_pipeline import run_unified_pipeline, run_batch_benchmark, MAX_PARALLEL_SANDBOXES
from museverify_stage2 import clean_worktrees
from reporting import RunReport, REPORT_DIR

ROOT = Path(__file__).resolve().parent
active_connections = []
_connection_locks = {}
_event_seq = itertools.count(1)
background_tasks = set()
_history = deque(maxlen=400)
_adhoc_seq = itertools.count(1)
_current_report = None
_job = None
session_policy = SessionPolicy()
sandbox_semaphore = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)
log = logging.getLogger(__name__)


def track(coro):
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    def completed(t):
        background_tasks.discard(t)
        if not t.cancelled() and t.exception():
            log.error('Background task failed: %s', type(t.exception()).__name__)
    task.add_done_callback(completed)
    return task


@asynccontextmanager
async def lifespan(app):
    yield
    for task in list(background_tasks):
        task.cancel()
    if background_tasks:
        await asyncio.gather(*list(background_tasks), return_exceptions=True)
    for ws in list(active_connections):
        try:
            await ws.close()
        except Exception:
            pass
    active_connections.clear()
    _connection_locks.clear()


app = FastAPI(title='AgentWard + MuseVerify Cockpit', lifespan=lifespan)


@app.middleware('http')
async def same_origin_controls(request: Request, call_next):
    # Local controls cannot be driven by an unrelated website in the browser.
    origin = request.headers.get('origin')
    if request.method == 'POST' and origin and origin.rstrip('/') != str(request.base_url).rstrip('/'):
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'Cross-origin control request rejected'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


class ModeRequest(BaseModel):
    mode: str


class SteerRequest(BaseModel):
    constraint: str = Field(min_length=1, max_length=2000)


@app.get('/api/providers')
async def providers(force_refresh: bool = False):
    registry = await discover_and_verify_providers(force_refresh)
    try:
        topology = select_ensemble(registry)
    except (ProviderUnavailable, ValueError) as exc:
        topology = {'mode': registry['mode'], 'members': [], 'notices': [str(exc) + '; runs are blocked']}
    return {**registry, 'topology': topology}


@app.post('/api/providers/mode')
async def provider_mode(req: ModeRequest):
    try:
        configuration_update(ensemble_mode=req.mode)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    result = await providers()
    await broadcast('providers', result)
    return result


@app.post('/api/steer')
async def steer(req: SteerRequest):
    try:
        snapshot = session_policy.tighten(req.constraint)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    # Pending approvals become stale immediately; the next boundary re-reviews.
    await broadcast('operator_policy', snapshot)
    return snapshot


@app.get('/api/executive-brief')
async def get_executive_brief():
    if _current_report:
        return await asyncio.to_thread(_current_report.brief)
    try:
        saved = json.loads(await asyncio.to_thread((REPORT_DIR / 'benchmark_metrics.json').read_text))
    except (OSError, ValueError):
        saved = {'records': []}
    return executive_brief(saved.get('records', []), {k: v for k, v in saved.items() if k != 'records'})


class AuditRequest(BaseModel):
    target_file: str


class CleanRequest(BaseModel):
    remove_all: bool = False


async def broadcast(event_type, data='', phase=0, status='', color='', note='', **context):
    if isinstance(data, (dict, list)):
        data = json.dumps(data)
    event = {'type': event_type, 'data': data, 'phase': phase, 'status': status,
             'color': color, 'note': note, 'sequence': next(_event_seq), **context}
    if event_type != 'metrics':
        _history.append(event)
    payload = json.dumps(event)
    async def send(ws):
        try:
            async with _connection_locks.setdefault(ws, asyncio.Lock()):
                await asyncio.wait_for(ws.send_text(payload), timeout=2)
        except Exception:
            if ws in active_connections:
                active_connections.remove(ws)
            _connection_locks.pop(ws, None)
    await asyncio.gather(*(send(ws) for ws in list(active_connections)))


def make_emitter(default_phase=0, default_color='slate'):
    def emit(event_type, data=None, phase=0, status='', color='', note=''):
        track(broadcast(event_type, data or {}, phase if isinstance(phase, (int, float)) else default_phase,
                        status, color or default_color, note))
    return emit


@app.get('/', response_class=HTMLResponse)
async def get_index():
    return await asyncio.to_thread((ROOT / 'templates/index.html').read_text)


@app.get('/api/health')
async def health():
    return {'status': 'ok', 'running': _job is not None and not _job.done(), 'phases': [1, 2, 3, 4, 4.5, 5, 5.1]}


@app.get('/api/metrics')
async def metrics():
    if _current_report:
        return _current_report.metrics()
    path = REPORT_DIR / 'benchmark_metrics.json'
    try:
        saved = json.loads(await asyncio.to_thread(path.read_text))
        return {k: v for k, v in saved.items() if k != 'records'}
    except (OSError, ValueError):
        return RunReport().metrics()


@app.get('/api/sarif')
async def export_sarif():
    path = REPORT_DIR / 'agentward_sarif_report.sarif'
    if not path.is_file():
        raise HTTPException(404, 'Run an audit to generate the SARIF report')
    return FileResponse(path, media_type='application/sarif+json', filename=path.name)


@app.websocket('/ws/telemetry')
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    # Replay before registering, so a concurrent send cannot interleave writes.
    for event in list(_history):
        await websocket.send_json(event)
    await websocket.send_json({'type': 'metrics', 'data': json.dumps(await metrics())})
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
        _connection_locks.pop(websocket, None)


def validate_target(target):
    path = Path(target)
    resolved = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if not resolved.is_relative_to(ROOT) or any(p in {'venv', '.venv', '.git', 'patches', 'worktrees', 'reports'} for p in resolved.relative_to(ROOT).parts):
        raise HTTPException(400, 'Target must be a source file in this workspace')
    if resolved.suffix != '.py' or not resolved.is_file():
        raise HTTPException(404, 'Python target not found')
    return str(resolved)


async def _run_job(target=None):
    global _current_report
    _current_report = RunReport()
    _history.clear()
    async def tick():
        while True:
            await broadcast('metrics', _current_report.metrics())
            await asyncio.sleep(1)
    ticker = track(tick())
    try:
        if target:
            await execute_harness(target, f'ADHOC-{next(_adhoc_seq):03d}', report=_current_report)
        else:
            await run_batch_benchmark_dashboard(report=_current_report)
    except Exception as exc:
        await broadcast('log', f'Run failed: {type(exc).__name__}: {exc}')
    finally:
        ticker.cancel()
        await asyncio.gather(ticker, return_exceptions=True)
        await asyncio.to_thread(_current_report.export)
        await broadcast('job_complete', {'metrics': _current_report.metrics()})


def start_job(target=None):
    global _job
    if _job is not None and not _job.done():
        raise HTTPException(409, 'An audit is already running; wait for completion')
    _job = track(_run_job(target))


@app.post('/api/run')
async def run_pipeline_api(req: AuditRequest):
    target = validate_target(req.target_file)
    start_job(target)
    return {'status': 'started', 'file': req.target_file}


@app.post('/api/batch')
async def run_batch_api():
    start_job()
    return {'status': 'started', 'concurrency': MAX_PARALLEL_SANDBOXES}


@app.post('/api/clean')
async def clean_workspaces_api(req: CleanRequest = CleanRequest()):
    if _job is not None and not _job.done():
        raise HTTPException(409, 'Workspace cleanup is unavailable while an audit is running')
    result = await asyncio.to_thread(clean_worktrees, remove_all=req.remove_all)
    return {'status': 'success', 'result': result}


async def execute_harness(target_file, vuln_id='VULN-001', *, report=None):
    return await run_unified_pipeline(target_file, vuln_id, on_event=broadcast, report=report,
                                      semaphore=sandbox_semaphore, policy=session_policy)


async def run_batch_benchmark_dashboard(targets_dir='benchmark_targets', *, report=None):
    return await run_batch_benchmark(targets_dir, on_event=broadcast, report=report,
                                     semaphore=sandbox_semaphore, policy=session_policy)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host=os.getenv('DASHBOARD_HOST', '127.0.0.1'), port=int(os.getenv('DASHBOARD_PORT', '8080')))

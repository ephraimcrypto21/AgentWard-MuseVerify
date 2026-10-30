"""Explicit offline demonstration: fake model responses, real sandbox and CodeShield.
Run with: AGENTWARD_FORCE_LOCAL=1 venv/bin/python -m tests.dry_run_dashboard
Production dashboard imports none of these fixtures.
"""
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import uvicorn
import ai_provider
import dashboard
import museverify_stage4
from reporting import RunReport
from tests.fixtures import fake_query, ROOT, offline_models

_real_batch = dashboard.run_batch_benchmark_dashboard
async def three_target_batch(*, report=None):
    with tempfile.TemporaryDirectory(prefix="agentward-dry-batch-") as directory:
        for name in ("poisoned_app.py", "cwe_89_sqli.py", "cwe_78_cmd.py", "fp_01.py"):
            source = ROOT/name if name == "poisoned_app.py" else ROOT/"benchmark_targets"/name
            (Path(directory)/name).write_text(source.read_text())
        return await _real_batch(directory, report=report)

if __name__ == '__main__':
    with offline_models(), patch.object(ai_provider, 'query_ai', fake_query), patch.object(museverify_stage4, 'query_ai', fake_query), patch.object(dashboard, 'RunReport', side_effect=lambda: RunReport(mode='dry_run')), patch.object(dashboard, 'run_batch_benchmark_dashboard', three_target_batch):
        uvicorn.run(dashboard.app, host='127.0.0.1', port=int(os.getenv('DRY_RUN_PORT', '18081')))

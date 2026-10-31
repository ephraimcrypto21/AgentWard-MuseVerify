"""Versioned, bounded input contract for remote sandbox execution."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from language_adapters import adapter_for

EVIDENCE_VERSION = 3
MAX_CODE_CHARS = 200_000
RESERVED_FILES = {'verify_test.py', 'verify_test.mjs', 'agentward_runner.py', 'bootstrap.py', 'run.sh'}


class SandboxRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    vuln_id: str = Field(default='VULN-001', max_length=128, pattern=r'^[A-Za-z0-9_.-]+$')
    target_file: str = Field(default='', max_length=128)
    target_filename: str = Field(default='', max_length=128)
    code_content: str = Field(default='', max_length=MAX_CODE_CHARS)
    sanitized_target_code: str = Field(default='', max_length=MAX_CODE_CHARS)
    test_code: str = Field(default='', max_length=MAX_CODE_CHARS)
    test_script: str = Field(default='', max_length=MAX_CODE_CHARS)
    poc_script: str = Field(default='', max_length=MAX_CODE_CHARS)
    capture_mode: Literal['auto'] = 'auto'
    language: Literal['python', 'javascript', 'typescript'] | None = None

    @model_validator(mode='after')
    def validate_artifacts(self):
        for names in [('target_file', 'target_filename'), ('code_content', 'sanitized_target_code'),
                      ('test_code', 'test_script', 'poc_script')]:
            values = {getattr(self, name) for name in names if getattr(self, name)}
            if len(values) > 1:
                raise ValueError('Conflicting artifact aliases')
        name = self.target_file or self.target_filename or 'target.py'
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\.[a-z]+', name) or name in RESERVED_FILES:
            raise ValueError('Target must be a non-reserved source filename')
        adapter = adapter_for(name)
        if self.language is not None and self.language != adapter.name:
            raise ValueError('Language does not match target extension')
        self.language = adapter.name
        if not (self.code_content or self.sanitized_target_code).strip():
            raise ValueError('Source is required')
        if not (self.test_code or self.test_script or self.poc_script).strip():
            raise ValueError('Harness is required')
        return self

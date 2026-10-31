#!/usr/bin/env python3
"""Build the reviewed 31 October 2026 project guide; no live services are queried.

Install requirements-docs.txt, then run this script from any directory.
Content intentionally describes a fixed application release. When revising it,
review the evidence ledger and source references, not just the revision/date.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile
from xml.sax.saxutils import escape
import argparse

from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
RELEASE = '59f8c1dac5cfde863d4e9ed62303b9f9e09ffc73'
DATE = '31 October 2026'
REPO = 'https://github.com/ephraimcrypto21/AgentWard-MuseVerify'
PAGE_COUNT = 16
PAGE_W, PAGE_H = A4
WIDTH = PAGE_W - 92
NAVY = colors.HexColor('#112A3A')
INK = colors.HexColor('#203747')
TEAL = colors.HexColor('#087E8B')
LIGHT = colors.HexColor('#EDF5F6')
MUTED = colors.HexColor('#536B79')
RULE = colors.HexColor('#D9E4E9')
WHITE = colors.white
FONT = 'Helvetica'
BOLD = 'Helvetica-Bold'
MONO = 'Courier'


def register_fonts():
    """Prefer embedded Lato; standard PDF fonts provide a portable fallback."""
    global FONT, BOLD, MONO
    font_root = Path('/usr/share/fonts/truetype/lato')
    if all((font_root / name).exists() for name in ('Lato-Regular.ttf', 'Lato-Bold.ttf', 'Lato-Italic.ttf', 'Lato-BoldItalic.ttf')):
        for name, file in (
            ('Guide', 'Lato-Regular.ttf'), ('GuideBold', 'Lato-Bold.ttf'),
            ('GuideItalic', 'Lato-Italic.ttf'), ('GuideBoldItalic', 'Lato-BoldItalic.ttf'),
        ):
            pdfmetrics.registerFont(TTFont(name, str(font_root / file)))
        pdfmetrics.registerFontFamily('Guide', normal='Guide', bold='GuideBold', italic='GuideItalic', boldItalic='GuideBoldItalic')
        FONT, BOLD = 'Guide', 'GuideBold'
    mono = Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
    if mono.exists():
        pdfmetrics.registerFont(TTFont('GuideMono', str(mono)))
        MONO = 'GuideMono'


def styles():
    return {
        'body': ParagraphStyle('body', fontName=FONT, fontSize=10.5, leading=15.3, textColor=INK, spaceAfter=8),
        'small': ParagraphStyle('small', fontName=FONT, fontSize=9.2, leading=13, textColor=INK, spaceAfter=7),
        'cell': ParagraphStyle('cell', fontName=FONT, fontSize=9.3, leading=13, textColor=INK),
        'headcell': ParagraphStyle('headcell', fontName=BOLD, fontSize=9, leading=12, textColor=WHITE),
        'title': ParagraphStyle('title', fontName=BOLD, fontSize=26, leading=30, textColor=NAVY, spaceAfter=11),
        'sub': ParagraphStyle('sub', fontName=BOLD, fontSize=12.5, leading=17, textColor=TEAL, spaceBefore=7, spaceAfter=5),
        'kicker': ParagraphStyle('kicker', fontName=BOLD, fontSize=9, leading=13, textColor=TEAL, spaceAfter=10),
        'code': ParagraphStyle('code', fontName=MONO, fontSize=8, leading=12.3, textColor=INK, spaceAfter=0),
        'cover': ParagraphStyle('cover', fontName=BOLD, fontSize=39, leading=45, textColor=WHITE, spaceAfter=19),
        'coverdeck': ParagraphStyle('coverdeck', fontName=FONT, fontSize=18, leading=25, textColor=colors.HexColor('#BDDFE5'), spaceAfter=20),
        'coverbody': ParagraphStyle('coverbody', fontName=FONT, fontSize=11, leading=16, textColor=WHITE, spaceAfter=10),
    }


S = {}
STORY = []
SOURCES = [
    'Application release 59f8c1d; evidence reviewed 31 October 2026',
    'README.md; docs/SKILLS.md; docs/INGRESS_GUARD.md; docs/DEPLOYMENT_V3.md',
    'docs/THREAT_MODEL.md; README.md; service_security.py; sandbox_protocol.py',
    'README.md; main_pipeline.py; docs/LANGUAGES.md',
    'docs/LANGUAGES.md; language_adapters.py; ecmascript_harness.py',
    'docs/INGRESS_GUARD.md; ingress_guard.py; security/ingress-model.lock.json',
    'docs/THREAT_MODEL.md; sandbox_server.py; sandbox_protocol.py',
    'README.md; museverify_stage4.py; main_pipeline.py; docs/LANGUAGES.md',
    'README.md; ai_provider.py; agentward_stage3.py; dashboard.py',
    'README.md; requirements-dev.txt; docs/INGRESS_GUARD.md',
    'docs/DEPLOYMENT_V3.md; docs/INGRESS_GUARD.md; deploy_remote_services.sh',
    'README.md; dashboard.py; reporting.py',
    'docs/SKILLS.md; security/skills.lock.json; repository modules at 59f8c1d',
    'docs/INGRESS_GUARD.md; docs/DEPLOYMENT_V3.md; local release records; CI',
    'docs/THREAT_MODEL.md; docs/LANGUAGES.md; docs/INGRESS_GUARD.md',
    'Versioned source references and document build instructions',
]


def p(text, style='body'):
    return Paragraph(text, S[style])


def para(text, style='body'):
    STORY.append(p(text, style))


def sub(text):
    para(text, 'sub')


def page(number, title, deck=None, bookmark=None):
    while STORY and isinstance(STORY[-1], Spacer):
        STORY.pop()
    STORY.append(PageBreak())
    para(f'{number:02d} / PROJECT GUIDE', 'kicker')
    heading = p(title, 'title')
    heading.bookmark = bookmark or f'page{number + 1}'
    STORY.append(heading)
    if deck:
        para(deck)


def table(headers, rows, widths):
    data = [[p(h, 'headcell') for h in headers]]
    data.extend([[p(c, 'cell') for c in row] for row in rows])
    tbl = Table(data, colWidths=[WIDTH * w for w in widths], hAlign='LEFT', repeatRows=1)
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), NAVY),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 6.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6.5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [LIGHT, WHITE]),
        ('LINEBELOW', (0, 1), (-1, -1), 0.4, RULE),
    ]))
    STORY.extend([tbl, Spacer(1, 10)])


def callout(title, text):
    box = Table([[p(f'<b>{title}</b><br/>{text}', 'body')]], colWidths=[WIDTH])
    box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
        ('LINEBEFORE', (0, 0), (0, -1), 3, TEAL),
        ('LEFTPADDING', (0, 0), (-1, -1), 14),
        ('RIGHTPADDING', (0, 0), (-1, -1), 14),
        ('TOPPADDING', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    STORY.extend([box, Spacer(1, 10)])


def code(text):
    body = '<br/>'.join(escape(line).replace(' ', '&#160;') for line in text.splitlines())
    box = Table([[p(body, 'code')]], colWidths=[WIDTH])
    box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
        ('BOX', (0, 0), (-1, -1), 0.5, RULE),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 11),
    ]))
    STORY.extend([box, Spacer(1, 11)])


class Architecture(Flowable):
    """Vector diagram with explicit execution and evidence boundaries."""
    def __init__(self):
        super().__init__()
        self.width, self.height = WIDTH, 298

    def draw(self):
        c = self.canv
        c.translate(0, 22)
        c.scale(1, 0.86)

        def label(text, x, y, width, size=9, color=INK, bold=False):
            style = ParagraphStyle('diagram', fontName=BOLD if bold else FONT, fontSize=size, leading=size + 3, textColor=color, alignment=TA_CENTER)
            obj = Paragraph(text, style)
            _, h = obj.wrap(width, 80)
            obj.drawOn(c, x, y - h)

        def box(x, y, width, height, title, detail, dark=False):
            c.setFillColor(NAVY if dark else LIGHT)
            c.setStrokeColor(RULE)
            c.roundRect(x, y, width, height, 7, fill=1, stroke=not dark)
            label(title, x + 7, y + height - 9, width - 14, 10, WHITE if dark else NAVY, True)
            label(detail, x + 7, y + height - 28, width - 14, 8.4, WHITE if dark else MUTED)

        def arrow(x1, y1, x2, y2, color=TEAL):
            c.setStrokeColor(color)
            c.setFillColor(color)
            c.setLineWidth(1.2)
            c.line(x1, y1, x2, y2)
            path = c.beginPath()
            if x1 == x2:
                sign = 1 if y2 > y1 else -1
                path.moveTo(x2, y2)
                path.lineTo(x2 - 3, y2 - 6 * sign)
                path.lineTo(x2 + 3, y2 - 6 * sign)
            else:
                sign = 1 if x2 > x1 else -1
                path.moveTo(x2, y2)
                path.lineTo(x2 - 6 * sign, y2 - 3)
                path.lineTo(x2 - 6 * sign, y2 + 3)
            path.close()
            c.drawPath(path, fill=1, stroke=0)

        box(0, 254, 144, 58, 'Operator + source', 'Browser or CLI<br/>untrusted source input')
        box(177, 254, 150, 58, 'Orchestrator', 'Policy, adapters, gates<br/>and evidence checks', True)
        box(360, 254, WIDTH - 360, 58, 'Model providers', 'Meta primary<br/>optional reviewers')
        arrow(144, 283, 177, 283)
        arrow(327, 283, 360, 283)
        label('Authenticated calls over the private tailnet', 20, 237, WIDTH - 40, 9, TEAL, True)
        c.setStrokeColor(TEAL)
        c.setDash(4, 3)
        c.roundRect(0, 49, WIDTH, 166, 8, stroke=1, fill=0)
        c.setDash()
        label('REMOTE VERIFICATION NODE / loopback services', 15, 205, WIDTH - 30, 8.5, TEAL, True)
        box(14, 111, 149, 66, 'Ingress service', 'Full-source classifier<br/>+ sanitizer rescan')
        box(177, 111, 149, 66, 'Sandbox service', 'Trusted root tracer<br/>+ immutable bootstrap')
        box(340, 111, WIDTH - 354, 66, 'Submitted payload', 'Docker / UID 65534<br/>no network; bounded')
        arrow(218, 254, 218, 218)
        arrow(326, 143, 340, 143)
        label('Bound source hashes<br/>classifier contract v2', 16, 97, 146, 8.5, MUTED)
        label('Protected kernel trace + artifact identity<br/>sandbox evidence protocol v3', 180, 97, WIDTH - 195, 8.5, MUTED)
        arrow(251, 49, 251, 28)
        box(119, -24, 265, 52, 'Verified gates -> reports + candidates', 'Evidence remains separate from model advice', True)


class GuideDocument(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        bookmark = getattr(flowable, 'bookmark', None)
        if bookmark:
            self.canv.bookmarkPage(bookmark)
            self.canv.addOutlineEntry(flowable.getPlainText(), bookmark, level=0)


def decoration(c, doc):
    c.saveState()
    c.setCreator('tools/build_project_guide.py')
    c.setDateFormatter(lambda *_: 'D:20261031000000Z')
    if doc.page == 1:
        c.setFillColor(NAVY)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        c.setFillColor(TEAL)
        c.rect(46, PAGE_H - 62, 76, 5, fill=1, stroke=0)
        c.setStrokeColor(colors.HexColor('#23495B'))
        for i in range(5):
            c.circle(PAGE_W + 30, 125, 115 + i * 24, stroke=1, fill=0)
        c.setFillColor(colors.HexColor('#BDDFE5'))
        c.setFont(FONT, 8.5)
        c.drawString(46, 38, f'CURRENT-STAGE EDITION  /  {DATE.upper()}')
        c.drawRightString(PAGE_W - 46, 38, f'1 / {PAGE_COUNT}')
    else:
        c.setFont(BOLD, 8)
        c.setFillColor(TEAL)
        c.drawString(46, PAGE_H - 34, 'AGENTWARD + MUSEVERIFY')
        c.setFillColor(MUTED)
        c.drawRightString(PAGE_W - 46, PAGE_H - 34, 'CURRENT-STAGE PROJECT GUIDE')
        c.setStrokeColor(RULE)
        c.line(46, 65, PAGE_W - 46, 65)
        c.setFont(FONT, 7.2)
        c.drawString(46, 52, SOURCES[min(doc.page - 1, len(SOURCES) - 1)])
        c.setFont(FONT, 8)
        c.drawString(46, 35, f'Application {RELEASE[:7]}  |  {DATE}')
        c.drawRightString(PAGE_W - 46, 35, f'{doc.page} / {PAGE_COUNT}')
    c.restoreState()


def content():
    STORY.append(Spacer(1, 36))
    para('AGENTWARD<br/>+ MUSEVERIFY', 'cover')
    para('Evidence-driven security<br/>for Python, JavaScript and TypeScript', 'coverdeck')
    para('Project guide / current-stage edition', 'coverbody')
    STORY.append(Spacer(1, 27))
    para('A Meta-primary harness that inspects source, reproduces supported vulnerabilities in Docker, proposes repairs and requires independent verification before accepting them.', 'coverbody')
    STORY.append(Spacer(1, 18))
    cover_metrics = Table([[p('<font color="#FFFFFF"><b>3 languages</b><br/>7 supported extensions</font>', 'body'), p('<font color="#FFFFFF"><b>7 phases</b><br/>One mandatory gate chain</font>', 'body'), p('<font color="#FFFFFF"><b>Protocol v3</b><br/>Deployed remote sandbox</font>', 'body')]], colWidths=[WIDTH / 3] * 3)
    cover_metrics.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#23495B')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 13), ('TOPPADDING', (0, 0), (-1, -1), 13), ('BOTTOMPADDING', (0, 0), (-1, -1), 10)]))
    STORY.append(cover_metrics)
    STORY.append(Spacer(1, 24))
    para('<b>Current release</b><br/>Source-aware ingress guard, protected runtime evidence, persistent private connectivity and a pinned library of 818 engineering skills.', 'coverbody')
    para('<b>Evidence snapshot</b><br/>78 classifier regression cases passed; 25 remote protocol-v3 acceptance groups passed. Their scope and dates are explained on page 14.', 'coverbody')
    STORY.append(Spacer(1, 14))
    para(f'Application snapshot <b>{RELEASE[:7]}</b><br/>{DATE}', 'coverbody')

    page(1, 'What the project is now', 'AgentWard + MuseVerify combines source inspection, controlled exploit reproduction and AI-assisted repair in a single evidence-driven workflow.', 'definition')
    sub('Purpose')
    para('The project helps an operator assess supported source files, distinguish reproducible vulnerabilities from inconclusive findings, and review candidate repairs with their supporting evidence. Model advice can propose a change; acceptance depends on the mandatory gates.')
    table(['Area', 'Current stage'], [
        ('Input', 'Python plus single-file JavaScript/TypeScript Node modules. Language adapters select the parser, harness and verification rules.'),
        ('Execution', 'Authenticated remote services and a deployed multilang-v3 Docker image; protected traces bind execution to the submitted artifacts.'),
        ('Ingress', 'A pinned source-aware classifier replaces the older Prompt-Guard model. Parser facts precede the complete source; sanitization requires a full rescan.'),
        ('Engineering', 'All 818 requested community cybersecurity skills are installed and pinned. Selected skills informed the hardening; runtime gates stay in application code.'),
        ('Operations', 'Both services run on loopback behind persistent private Tailscale forwarding. Workstation integration was verified after SSH disconnected.'),
    ], [.20, .80])
    sub('Read this guide by task')
    table(['Task', 'Pages'], [
        ('Understand the architecture and supported inputs', '<link href="#architecture" color="#087E8B">3-5</link>'),
        ('Understand detection, evidence and repair acceptance', '<link href="#ingress" color="#087E8B">6-8</link>'),
        ('Run and operate the system', '<link href="#providers" color="#087E8B">9-12</link>'),
        ('Review implementation, results and coverage limits', '<link href="#repository" color="#087E8B">13-16</link>'),
    ], [.80, .20])

    page(2, 'Architecture and trust boundaries', 'The workstation coordinates policy and verification. Submitted source and model output remain untrusted throughout the workflow.', 'architecture')
    STORY.append(Architecture())
    STORY.append(Spacer(1, 22))
    sub('What must be trusted')
    para('The operator configuration, application services, selected provider identities, Docker host and kernel, runtime image, bootstrap and tracer form the trusted base. A compromised host or service can undermine the evidence it produces.')
    sub('What evidence establishes')
    para('Authentication controls who can request work. Hashes bind results to particular source and harness artifacts. Protected kernel traces record selected execution behavior. The orchestrator combines that evidence with positive controls, reviews and regression results.')
    callout('Two different contracts', '<b>Classifier contract v2</b> binds model, policy, language and source hashes. <b>Sandbox protocol v3</b> binds protected runtime evidence, artifact hashes, language, runtime and filename. Both must match the workstation.')

    page(3, 'The seven-phase workflow', 'Every supported language uses the same orchestrator. A failed or unavailable required gate prevents a verified repair.', 'pipeline')
    table(['Phase', 'Work performed', 'Acceptance evidence'], [
        ('<b>1 / Ingress Shield</b>', 'Classify complete source and sanitize injected instructions.', 'Full coverage, rescan after changes, exact model/policy contract and source hashes.'),
        ('<b>2 / Syscall Sandbox</b>', 'Reproduce supported exploits with deterministic probes in Docker.', 'Protected strace evidence, artifact identity and completed behavioral probes.'),
        ('<b>3 / Runtime Hooks</b>', 'Apply screening, ensemble policy checks and trajectory monitoring.', 'Valid unanimous votes and the current operator policy revision; violations trigger rewind.'),
        ('<b>4 / Patch Verification</b>', 'Synthesize a repair; inspect contracts, static paths, reviews, CodeShield and tripwires.', 'All applicable structural, scanner and independent-review gates pass.'),
        ('<b>4.5 / Adversarial Self-Play</b>', 'Replay bounded mutated and multi-step scenarios.', 'Original-code positive controls succeed; no surviving exploit in the candidate; valid evidence.'),
        ('<b>5 / Regression</b>', 'Replay exploits, normal inputs and decoy probes.', 'Exploit blocked; functional checks preserved; tripwire fires only for decoys.'),
        ('<b>5.1 / Semantic Hunter</b>', 'Inspect related modules and semantic paths with Wonder-led analysis.', 'Static findings and unresolved assumptions remain visible, separate from runtime proof.'),
    ], [.22, .37, .41])
    sub('Concurrency and reporting')
    para('Phase 2 overlaps with graph construction and the initial policy baseline. The pipeline runs at most three containers concurrently. Passing that baseline cannot replace the later sandbox, patch or regression evidence.')
    para('Reports distinguish simulated outcomes, static findings and runtime-verified outcomes. Semantic hunting can identify additional review work beyond the behavior exercised by the repair probes.', 'small')

    page(4, 'Supported languages and targets', 'Language support means a defined parser, execution harness and verification contract. It does not imply arbitrary project builds.', 'languages')
    table(['Language', 'Files', 'Supported verification scope'], [
        ('Python', '.py', 'Existing Python parsing, graph analysis and benchmark probes.'),
        ('JavaScript', '.js / .mjs / .cjs', 'Single-file Node ES/CommonJS modules with compatible exported SQL/command functions.'),
        ('TypeScript', '.ts / .mts / .cts', 'The same Node probes with erasable syntax. Original source executes in Node 24; scanning uses AST-based type erasure.'),
    ], [.19, .26, .55])
    sub('Node target contract')
    para('Node targets support named top-level functions and arrow functions in ES/CommonJS exports. All exports (maximum eight) must accept a single scalar SQL/command probe argument and return serializable results. Ambiguous or partial probe coverage is rejected.')
    para('Execution uses built-in Node dependencies. Normal regression uses <b>agentward_normal</b>; other business contracts need additional probes. Node always runs in Docker, including fixture-model demonstrations.')
    sub('TypeScript behavior')
    para('Tree-sitter parses without execution. Type-only nodes are erased and reparsed as JavaScript for CodeShield. Original TypeScript executes in Docker. Supported syntax includes annotations, interfaces, type aliases, generics and as-assertions; there is no type checking.')
    table(['Result', 'Meaning'], [
        ('UNSUPPORTED_LANGUAGE', 'Extension outside the registry: for example Go, Java, Rust, JSX or TSX.'),
        ('INVALID_SOURCE', 'Syntax is invalid for the selected language.'),
        ('UNSUPPORTED_TARGET', 'The supported language has no fully compatible Node probe surface.'),
    ], [.43, .57])
    callout('Outside the current target contract', 'Browser apps, npm dependencies, multi-file execution, constructed classes and project compiler plugins are unsupported. TypeScript enums, namespaces, decorators and unsupported transformations cannot pass the complete chain.')

    page(5, 'Ingress: detection with context', 'The ingress guard detects instructions aimed at manipulating the audit. It is a separate task from finding vulnerabilities in the program.', 'ingress')
    sub('How the current guard works')
    para('The <b>Horizon-Labs/prompt-injection-guard-small</b> model, pinned at revision <b>5ed691c</b> under Apache-2.0, receives bounded parser facts followed by the complete source. The prefix describes language, declared names and syntax-node kinds; it never declares the source safe. Valid syntax and filenames cannot bypass classification.')
    table(['Control', 'Current behavior'], [
        ('Coverage', '512-token windows with 128-token overlap; the highest injection score controls the decision. Risk threshold: 0.40.'),
        ('Work bound', 'At most 256 windows per original or sanitized input. Over-limit or incomplete coverage is denied, without silently truncating source.'),
        ('Sanitization', 'Recognizes explicit role-directed bypass or fabricated-audit instructions in comments/literals, including decoded base64. Modified source receives a full rescan.'),
        ('Model integrity', 'Five artifacts are pinned and SHA-256 verified. Safetensors, no remote code, no inference-time downloads; provisioning is explicit.'),
        ('Evidence', 'Contract v2 binds the model revision and policy identity, language and original/sanitized hashes. Stale or mismatched responses cannot authorize a live run.'),
    ], [.23, .77])
    callout('What “detection remains probabilistic” means', 'The model assigns a learned risk score. It can occasionally flag harmless code or miss an unfamiliar instruction attack. <b>78 of 78 regression cases passed</b> means those specific cases behaved as expected; it does not mean every future input will be classified correctly.')
    para('The 0.40 threshold is a decision setting, not a measured 40% chance that a program is unsafe. Ingress ALLOW means the file can proceed to the next checks; a vulnerable SQL or command function may correctly pass ingress and then fail sandbox verification.', 'small')
    para('The older model produced the reported Node false positives. The replacement resolved those tested cases while retaining separate sandbox, review, scanner and regression requirements.', 'small')

    page(6, 'Protected runtime evidence', 'The remote sandbox executes submitted code under a fixed, constrained runtime and keeps the evidence outside the payload’s control.', 'sandbox')
    table(['Boundary', 'Enforced control'], [
        ('Identity', 'Bearer authentication and bounded request schemas. Protocol v3 binds source/harness SHA-256, language, runtime and target filename.'),
        ('Privileges', 'Trusted root tracer and immutable bootstrap start first. Submitted code runs only after UID/GID drop to 65534, group clearing and capability removal.'),
        ('Filesystem / network', 'No container network. Read-only root, source inputs and bootstrap; bounded 64 MiB workspace and 16 MiB temporary storage.'),
        ('Trace protection', 'Root-owned kernel trace in a POSIX-ACL-protected directory. Payloads cannot read, overwrite, unlink or replace host-backed evidence.'),
        ('Resources', '256 MiB memory/swap ceilings, CPU/PID limits and bounds on time, output, trace bytes and event counts. Overflow and timeout deny evidence and trigger cleanup.'),
        ('Runtime choice', 'Fixed python3/node allowlist. Python isolated startup; Node loader environment variables cleared. No arbitrary caller-selected interpreter.'),
    ], [.24, .76])
    sub('Conditions for accepted execution evidence')
    para('The client requires matching protocol and artifact identity plus complete protected traces and valid behavioral results. Missing traces, tampering, truncation, abnormal completion and unsupported ownership/ACL setup deny evidence. Docker failure cannot trigger production host execution.')
    callout('Deployment requirements', 'The supported node uses rootful Linux Docker without user-namespace remapping and an ACL-capable temporary filesystem. Rootless or remapped configurations are not validated.')
    para('Evidence is authenticated and hash-bound, not digitally signed. Selected syscalls and payload-produced probe lines cannot prove all possible behavior; the other acceptance gates remain necessary.', 'small')

    page(7, 'How a repair earns acceptance', 'A proposed patch stays a candidate until independent checks agree with the observed behavior.', 'repairs')
    sub('Preserve the public contract')
    para('Patch checks preserve relevant function interfaces and sync/async behavior. Node checks also compare exported parameters and type signatures. Model-generated text cannot waive structural rules, scanning or current operator restrictions.')
    sub('Use independent evidence at each step')
    table(['Gate', 'What it contributes'], [
        ('Policy and review', 'Valid votes from the selected reviewers, bound to current additive operator constraints. Missing or malformed reviewer output denies approval.'),
        ('Static checks and CodeShield', 'Contract inspection, call/taint findings and scanner results. TypeScript is erased and reparsed for JavaScript rules; execution uses the original source.'),
        ('Structural tripwire', 'An AST-recognized decoy equality guard plus a logging action. Text that merely mentions a canary cannot satisfy this check.'),
        ('Adversarial replay', 'Deterministic mutations and bounded scenarios run against original and candidate code. Original-code positive controls must reproduce the relevant behavior.'),
        ('Regression', 'The original exploit is blocked, tested normal results are preserved, and the tripwire fires only for decoy probes.'),
    ], [.27, .73])
    sub('Bounded self-play')
    para('Models propose scenarios in a bounded scenario language. The system uses deterministic harnesses for storage/replay, URL decoding, cleanup and supported interleaving checks. It does not execute arbitrary model-written self-play harnesses. Supported scenarios vary by adapter.')
    para('A storage adapter tests replay robustness; it may not demonstrate a native persistence flaw. Unsupported scenarios or failed positive controls cannot be counted as neutralized.', 'small')
    callout('Keep candidates and evidence reviewable', 'Accepted candidates and exact diffs are written to <b>patches/&lt;run-id&gt;/</b>. Benchmark targets remain intentionally vulnerable. Additional semantic findings and coverage limits stay visible in the report.')

    page(8, 'Providers and operator control', 'Meta remains mandatory for every live run. Optional providers add independent review when they pass pre-flight.', 'providers')
    para('<b>muse-spark-1.3</b> leads runtime policy and patch synthesis. <b>muse-wonder-1.0</b> leads deeper semantic analysis. In Meta-only operation, the two native models cross-check each other.')
    table(['Mode', 'Selected participants'], [
        ('auto', 'Meta primary plus every healthy secondary.'),
        ('all_three', 'Meta, Anti-Gravity and Custom; notices identify unavailable secondary providers.'),
        ('meta_plus_agy', 'Meta plus verified Anti-Gravity.'),
        ('meta_plus_custom', 'Meta plus verified Custom BYOK.'),
        ('meta_only', 'Spark and Wonder cross-check each other.'),
    ], [.31, .69])
    para('When no requested secondary passes pre-flight, Meta’s other native model supplies the independent review. If Meta is offline, a live run cannot proceed. A selected reviewer that later fails cannot silently become an approval.')
    sub('Pre-flight and configuration')
    para('Provider discovery runs concurrently and caches dashboard status for 60 seconds. A forced refresh reloads .env. Each run retains its successful discovery snapshot while configuration is unchanged; task failures still deny approval. Configure META_API_KEY, ENSEMBLE_MODE and optional Anti-Gravity or Custom endpoint/model credentials locally.')
    sub('Steer the running session')
    code('POST /api/steer\n{"constraint":"Forbid subprocess calls; enforce pathlib commonpath"}')
    para('Restrictions are additive and shared across batch workers. A monotonically increasing policy revision invalidates stale in-flight approval. Recognized subprocess/path restrictions have AST enforcement; broader natural-language restrictions also require model assessment.')
    callout('Control remains with the operator', 'Trajectory monitoring can halt and rewind a session for policy violations. No UI control waives a mandatory gate. General natural-language steering is not a complete formal policy language.')

    page(9, 'Start a supported audit', 'Use the local dashboard or CLI after configuring the providers and authenticated verification-node endpoints.', 'quickstart')
    sub('1 / Prepare the workstation')
    code('python3 -m venv venv\n. venv/bin/activate\npython -m pip install -r requirements-dev.txt\ncp .env.example .env')
    para('Python 3.12+ is recommended. Populate the local .env with Meta credentials, the shared AGENTWARD_NODE_TOKEN, and AGENTWARD_INGRESS_URL / AGENTWARD_SANDBOX_URL. Keep secrets out of Git. The deployed private-node setup is described on the next page.', 'small')
    sub('2 / Start the dashboard')
    code('python -m uvicorn dashboard:app --host 127.0.0.1 \\\n  --port 8080 --ws-max-size 1024 --ws-max-queue 4')
    para('Open <link href="http://127.0.0.1:8080" color="#087E8B">http://127.0.0.1:8080</link>. Inspect the real provider pre-flight matrix, select an ensemble and choose a benchmark or a source path within the workspace. Retest credentials when configuration changes.', 'small')
    sub('3 / Run a known target')
    code('python main_pipeline.py benchmark_targets/cwe_78_cmd.js\npython main_pipeline.py benchmark_targets/cwe_89_sqli.ts\npython main_pipeline.py poisoned_app.py')
    para('The CLI and dashboard use the same language adapters and mandatory gates. Inspect each phase, the exact diff and the evidence-derived executive brief before integrating an accepted candidate.', 'small')
    callout('A useful first comparison', '<b>cwe_78_cmd.js</b> and <b>cwe_89_sqli.ts</b> exercise vulnerable command/SQL paths. <b>fp_node.mjs</b> is the benign Node control. Passing ingress is expected for all three: the sandbox then distinguishes the tested runtime behavior.')
    para('Fixture-mode demonstrations have SIMULATED labels and cannot export verified SARIF fixes. Any permitted Python host execution is test-only; Node still requires Docker. See README.md for the explicit offline-demo commands.', 'small')

    page(10, 'Deployed services and operations', 'The coordinated workstation, service and sandbox upgrade is complete in the recorded deployment. This guide describes that snapshot; it does not perform a new deployment.', 'operations')
    table(['Component', 'Recorded state'], [
        ('Application', 'Release 59f8c1d with the matching workstation and ingress contract.'),
        ('Remote services', 'Ingress and sandbox systemd services enabled and active, bound to 127.0.0.1.'),
        ('Private connection', 'Persistent Tailscale Serve forwards ports 8000/8001 to the loopback services. Connectivity was verified after SSH disconnected.'),
        ('Sandbox image', 'agentward-sandbox:multilang-v3; recorded runtime versions Node 24.22.2 and Python 3.12.16, plus strace.'),
        ('Authentication', 'Shared random node token in a root-owned mode-0600 node file and the ignored workstation .env. Execution/classification aliases require it.'),
    ], [.27, .73])
    sub('Upgrade as a coordinated release')
    para('Deploy the full checkout and node requirements; provision and verify the pinned model; build the sandbox image; restart both services and the dashboard with matching contracts. deploy_remote_services.sh automates node setup and preserves an existing token. Do not mix a new client with stale service evidence.')
    sub('Check the operational boundaries')
    para('Use each service’s /health endpoint for connectivity, then authenticated ingress and execution controls for functional acceptance. A missing or short configured token produces HTTP 503; missing or incorrect request authorization produces 401. Exhausted classifier or sandbox slots produce 429 with Retry-After.')
    para('Keep the dashboard on loopback or behind authenticated access. Exact host/origin checks protect browser requests but do not authenticate native clients. Restrict tailnet access to the intended operators. Node requests disable redirects and ambient HTTP proxies.', 'small')
    callout('Rollback and recovery', 'Pre-upgrade application, environment and service-unit backups were retained on the node. Restore a matching workstation/service/image set. An older unauthenticated node cannot serve as valid protocol-v3 verification. The repository deployment record contains the recovery details.')

    page(11, 'Dashboard, API and artifacts', 'The interface exposes progress and evidence without allowing advisory text to override a verified outcome.', 'interface')
    table(['Interface', 'Operator use'], [
        ('GET /api/health<br/>GET /api/languages', 'Inspect running state, phase identifiers, language extensions and adapter scope.'),
        ('GET /api/providers<br/>POST /api/providers/mode', 'Inspect pre-flight and select an ensemble. force_refresh=true retests provider configuration.'),
        ('POST /api/run<br/>POST /api/batch', 'Audit a supported workspace source path or run a bounded benchmark batch.'),
        ('POST /api/steer<br/>POST /api/clean', 'Add a session restriction; prune temporary workspaces only when idle.'),
        ('GET /api/metrics<br/>GET /api/executive-brief', 'Read outcomes, usage and timing, plus evidence, assumptions and graphs.'),
        ('GET /api/sarif<br/>WebSocket /ws/telemetry', 'Export SARIF v2.1.0 or consume replayable events tagged by run.'),
    ], [.43, .57])
    sub('Review surfaces')
    para('The dashboard includes seven phase cards, replayable telemetry, a unified/side-by-side diff viewer, an executive brief and a cross-file call/taint map. Advisory model commentary is labeled and cannot change the outcome established by the gates.')
    table(['Artifact', 'Contents'], [
        ('patches/&lt;run-id&gt;/', 'Accepted candidates and exact diffs; original benchmarks stay unchanged.'),
        ('reports/benchmark_metrics.json', 'Per-file results, reviewer votes, pre-flight state, usage and latency.'),
        ('reports/agentward_sarif_report.sarif', 'Findings and eligible verified fixes in SARIF format.'),
        ('reports/executive_brief.md / .html', 'Evidence-derived assessment with unresolved assumptions and coverage limits.'),
    ], [.49, .51])
    para('Reports are written atomically and archived per run. Runtime reports, local workspaces and credentials are excluded from Git. They are operator-writable records, not a signed append-only audit log.', 'small')

    page(12, 'Codebase and skill integration', 'The implementation separates orchestration, model access, language rules, service security and evidence contracts.', 'repository')
    table(['Module / area', 'Responsibility'], [
        ('main_pipeline.py / dashboard.py', 'Orchestration, CLI, session state, API and live telemetry.'),
        ('ai_provider.py / agentward_stage3.py', 'Provider discovery, routing, runtime policy and trajectory checks.'),
        ('language_adapters.py<br/>ecmascript_harness.py', 'Language registry, parsers, contracts, sanitization hooks and deterministic Node probes.'),
        ('agentward_stage1.py / ingress_server.py<br/>ingress_guard.py / ingress_sanitizer.py', 'Ingress client/service, source-aware inference, sanitization and classifier evidence.'),
        ('sandbox_server.py / sandbox_protocol.py<br/>service_security.py', 'Constrained execution, protected trace protocol, authentication and bounded schemas.'),
        ('museverify_stage4.py / security_graph.py<br/>semantic_hunter.py / reporting.py', 'Patch gates, static paths, semantic findings and evidence-derived outputs.'),
        ('security/ / systemd/ / tests/ / docs/', 'Pins, Dockerfile, service units, regression corpora, tests and architecture records.'),
    ], [.50, .50])
    sub('818 pinned community cybersecurity skills')
    para('All skills from the requested independent community repository are installed locally for Codex. security/skills.lock.json pins source revision <b>54a7988</b> and full-tree hashes. Per-skill licenses and supporting material are preserved. The collection is not affiliated with Anthropic.')
    para('Tool-invocation security, container hardening, WebSocket testing, host-header testing and threat-modeling skills informed the controls documented here. This does not claim that every skill was executed or that its procedures establish compliance.', 'small')
    code('python3 tools/manage_cybersecurity_skills.py install\npython3 tools/manage_cybersecurity_skills.py verify')
    callout('Guidance has a defined role', 'The application does not load all 818 skills as runtime instructions or execute their scripts automatically. Installing them does not add language adapters or authorize testing outside the operator’s requested scope.')

    page(13, 'What has been verified', 'Evidence reviewed for application release 59f8c1d on 31 October 2026. Different checks establish different parts of the system.', 'validation')
    table(['Evidence set', 'Recorded result', 'What the result supports'], [
        ('Automated release checks', '<b>92 tests</b>', '91-test full suite passed with real Docker and no skips; an additional corpus-validity test passed. GitHub CI passed for the release.'),
        ('Real ingress model', '<b>78 / 78 cases</b><br/>45 benign + 33 malicious', 'Benign inputs stayed unchanged and passed. Malicious instructions were blocked or sanitized and successfully rescanned.'),
        ('Remote protocol-v3 deployment', '<b>25 acceptance groups</b>', 'Authenticated service aliases, all seven extensions, artifact/language binding, real isolation and exploit/fixture-repair controls. Recorded before the later classifier replacement.'),
        ('Latest live integration', '<b>4 benchmark paths</b><br/>+ 2 syntax controls', 'After guard deployment: real ingress and Docker for Python/JS command, TS SQL and benign Node. Additional TS object-literal and CommonJS source passed ingress.'),
        ('Earlier browser acceptance', '<b>JS/TS paths passed</b>', 'Simulated runs through the source-path UI, unsupported-language handling and zero page errors. This was not a live provider acceptance run.'),
    ], [.27, .23, .50])
    sub('How to read the classifier result')
    para('The 78 cases include the reported false positives, normal object literals and exports, multilingual instructions, base64, long inputs, fake metadata and repeated documentation. These corpora were used during policy development. The result is regression evidence, not an accuracy estimate from an untouched holdout population.')
    callout('The current live acceptance boundary', 'The latest checks used the real classifier and real Docker. Repair checks used deterministic fixtures. They did <b>not</b> repeat a full live, model-generated seven-phase remediation run or revalidate current provider availability.')
    para('The 30 October live-provider record belongs to an older application snapshot. It is retained as history in docs/VERIFICATION.md and is not presented as current acceptance.', 'small')

    page(14, 'Interpreting results and limits', 'Use each outcome as evidence for the behavior and coverage actually checked. A completed run is not a formal proof of program safety.', 'limits')
    table(['Result or signal', 'Interpretation'], [
        ('Ingress ALLOW / SANITIZED', 'The source may continue to the remaining gates. This is not a vulnerability verdict.'),
        ('Ingress BLOCKED / UNVERIFIED', 'A classified attack was denied, or required evidence was absent/stale. The pipeline records an ingress-blocked outcome when live ingress cannot pass.'),
        ('REMEDIATED', 'Applicable gates and tested repair behavior passed with production evidence. Review the diff and stated assumptions before integrating it.'),
        ('FALSE_POSITIVE', 'The tested suspected vulnerability was not confirmed and the required safe-path evidence passed. This is distinct from a classifier false positive.'),
        ('SIMULATED_*', 'Fixture-based demonstration. It cannot establish a production repair or export a verified SARIF fix.'),
        ('INCONCLUSIVE / rejected / failed', 'Evidence, policy, repair or regression requirements were not satisfied. Missing evidence is never an implicit pass.'),
    ], [.37, .63])
    sub('Coverage that remains bounded')
    para('<b>Detection:</b> unfamiliar instructions can evade the learned model; benign code can still be misclassified. New regressions should expand the corpus and trigger review of the pinned policy and model.')
    para('<b>Program analysis:</b> Python propagation is bounded; Node taint analysis is intraprocedural. Reflection, closures, dynamic dispatch, external libraries and Node cross-file flows need additional review. CodeShield coverage is narrower than a complete security audit.')
    para('<b>Runtime and operations:</b> selected probes and syscall traces cover observed behavior. The kernel, daemon, service, tracer and operator remain trusted. The shared token identifies an authorized workstation, not an individual user; provider data handling remains an operator decision.')
    callout('A useful next validation step', 'For a new production target, add representative functional probes and run the full live pipeline with fresh provider pre-flight. Expand adapters explicitly for new languages, application shapes and vulnerability families. These are extension directions, not shipped capabilities.')

    page(15, 'References and reproducibility', 'The PDF is a reviewed snapshot. Versioned repository documents and their implementation provide the detailed source of each claim.', 'references')
    table(['Reference', 'Use it for'], [
        ('<link href="' + REPO + '/blob/' + RELEASE + '/README.md" color="#087E8B">README.md</link>', 'Setup, provider configuration, API routes and complete verification commands.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/INGRESS_GUARD.md" color="#087E8B">docs/INGRESS_GUARD.md</link>', 'Classifier policy, model pin, regression evaluation and deployment.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/THREAT_MODEL.md" color="#087E8B">docs/THREAT_MODEL.md</link>', 'Trust boundaries, threat inventory and residual limits.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/LANGUAGES.md" color="#087E8B">docs/LANGUAGES.md</link>', 'Adapter contracts, syntax and execution limits.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/DEPLOYMENT_V3.md" color="#087E8B">docs/DEPLOYMENT_V3.md</link>', 'Recorded remote acceptance and coordinated rollback.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/SKILLS.md" color="#087E8B">docs/SKILLS.md</link>', 'Community provenance, exact pin and applied skills.'),
    ], [.47, .53])
    para('<link href="' + REPO + '/actions/runs/41249605568" color="#087E8B">Release CI run</link> provides the automated release record. Detailed live acceptance JSON remains in ignored local reports; those files are not part of the published guide.', 'small')
    sub('Reproduce checks and rebuild this guide')
    code('python -m unittest discover -v\npython -m pip check\npython tools/manage_ingress_model.py verify\npython tools/evaluate_ingress_guard.py \\\n  --output reports/ingress-regression.json')
    para('The model commands require the provisioned node dependencies and pinned artifacts. docs/INGRESS_GUARD.md lists the two additional corpora needed to reproduce all 78 cases; README.md lists the real Docker and live E2E checks.', 'small')
    para('The maintained PDF source is <b>tools/build_project_guide.py</b>. Install <b>requirements-docs.txt</b>, then run the generator. output/pdf/README.md records the build and review process. Rebuilding the PDF does not query services or establish new acceptance.', 'small')
    para('<b>Terms:</b> AST: abstract syntax tree. BYOK: bring your own API key. CWE: Common Weakness Enumeration. SARIF: Static Analysis Results Interchange Format. Positive control: an original-code test that must reproduce the expected vulnerable behavior.', 'small')
    para(f'<b>Application revision:</b> {RELEASE}', 'small')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'output/pdf/AgentWard_MuseVerify_Project_Guide.pdf')
    args = parser.parse_args()
    register_fonts()
    S.update(styles())
    rl_config.invariant = 1
    content()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=args.output.parent, suffix='.pdf', delete=False) as temp:
        temporary_output = Path(temp.name)
    try:
        doc = GuideDocument(
            str(temporary_output), pagesize=A4, rightMargin=46, leftMargin=46,
            topMargin=66, bottomMargin=74, pageCompression=1,
            title='AgentWard + MuseVerify | Current-stage project guide',
            author='AgentWard + MuseVerify project',
            subject=f'Reviewed {DATE}; application release {RELEASE[:7]}',
        )
        doc.build(STORY, onFirstPage=decoration, onLaterPages=decoration)
        if doc.page != PAGE_COUNT:
            raise RuntimeError(f'Expected {PAGE_COUNT} pages, produced {doc.page}; review layout before publishing')
        temporary_output.chmod(0o644)
        temporary_output.replace(args.output)
    finally:
        temporary_output.unlink(missing_ok=True)
    print(f'Wrote {args.output} ({doc.page} pages)')


if __name__ == '__main__':
    main()

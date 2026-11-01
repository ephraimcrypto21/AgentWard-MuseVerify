#!/usr/bin/env python3
"""Build the reviewed 1 November 2026 PDF and HTML guide without live queries.

Install requirements-docs.txt, then run this script from any directory.
Content intentionally describes a fixed application release. When revising it,
review the evidence ledger and source references, not just the revision/date.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile
from xml.sax.saxutils import escape
import argparse
import re

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
RELEASE = '2d52f29a585abf5c4dc241bdda118b5834c63126'
DATE = '1 November 2026'
REPO = 'https://github.com/ephraimcrypto21/AgentWard-MuseVerify'
PAGE_COUNT = 20
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
HTML = []
SOURCES = [
    'Application release 2d52f29; evidence reviewed 1 November 2026',
    'README.md; docs/SKILLS.md; docs/INGRESS_GUARD.md; docs/DEPLOYMENT_V3.md',
    'docs/THREAT_MODEL.md; README.md; service_security.py; sandbox_protocol.py',
    'README.md; main_pipeline.py; docs/LANGUAGES.md',
    'docs/LANGUAGES.md; language_adapters.py; ecmascript_harness.py',
    'docs/INGRESS_GUARD.md; ingress_guard.py; security/ingress-model.lock.json',
    'docs/THREAT_MODEL.md; sandbox_server.py; sandbox_protocol.py',
    'agentward_stage3.py; enforce_permissions.py; session_policy.py; main_pipeline.py',
    'README.md; museverify_stage4.py; main_pipeline.py; docs/LANGUAGES.md',
    'README.md; ai_provider.py; agentward_stage3.py; dashboard.py',
    'ai_provider.py; .env.example; service_security.py',
    'README.md; requirements-dev.txt; docs/INGRESS_GUARD.md',
    'docs/DEPLOYMENT_V3.md; docs/INGRESS_GUARD.md; deploy_remote_services.sh',
    'README.md; docs/DEPLOYMENT_V3.md; service_security.py',
    'README.md; dashboard.py; reporting.py',
    'docs/SKILLS.md; security/skills.lock.json; repository modules at 2d52f29',
    'docs/CORPUS_ACCEPTANCE_2026-11-01.md; docs/INGRESS_GUARD.md; docs/DEPLOYMENT_V3.md',
    'docs/CORPUS_ACCEPTANCE_2026-11-01.md; reports/corpus-2026-11-01/ (local evidence)',
    'docs/THREAT_MODEL.md; docs/LANGUAGES.md; docs/INGRESS_GUARD.md',
    'Versioned source references and document build instructions',
]


def html_fragment(text):
    """Translate the controlled ReportLab paragraph markup for the companion."""
    text = text.replace('<link ', '<a ').replace('</link>', '</a>')
    text = re.sub(r'(<a\b[^>]*?) color="[^"]*"', r'\1', text)
    text = re.sub(r'<font color="([^"]*)">', r'<span style="color:\1">', text)
    return text.replace('</font>', '</span>')


def p(text, style='body'):
    return Paragraph(text, S[style])


def para(text, style='body'):
    STORY.append(p(text, style))
    tag = 'h3' if style == 'sub' else 'h1' if style == 'cover' else 'p'
    HTML.append(f'<{tag} class="{style}">{html_fragment(text)}</{tag}>')


def sub(text):
    para(text, 'sub')


def page(number, title, deck=None, bookmark=None):
    while STORY and isinstance(STORY[-1], Spacer):
        STORY.pop()
    STORY.append(PageBreak())
    anchor = bookmark or f'page{number + 1}'
    HTML.append(f'</section><section id="{anchor}">')
    para(f'{number:02d} / PROJECT GUIDE', 'kicker')
    heading = p(title, 'title')
    heading.bookmark = bookmark or f'page{number + 1}'
    STORY.append(heading)
    HTML.append(f'<h2>{escape(title)}</h2>')
    if deck:
        para(deck)


def table(headers, rows, widths):
    HTML.append('<div class="table-scroll"><table><thead><tr>' + ''.join(
        '<th scope="col">' + html_fragment(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join('<td>' + html_fragment(c) + '</td>' for c in row) + '</tr>' for row in rows) + '</tbody></table></div>')
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
    HTML.append(f'<aside><strong>{html_fragment(title)}</strong><p>{html_fragment(text)}</p></aside>')
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
    HTML.append('<pre><code>' + escape(text) + '</code></pre>')
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
        label('Authenticated calls over loopback, SSH or a private tailnet', 20, 237, WIDTH - 40, 9, TEAL, True)
        c.setStrokeColor(TEAL)
        c.setDash(4, 3)
        c.roundRect(0, 49, WIDTH, 166, 8, stroke=1, fill=0)
        c.setDash()
        label('VERIFICATION NODE / loopback services', 15, 205, WIDTH - 30, 8.5, TEAL, True)
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
    c.setDateFormatter(lambda *_: 'D:20261101000000Z')
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
    HTML.append('<section class="cover" id="cover">')
    STORY.append(Spacer(1, 36))
    para('AGENTWARD<br/>+ MUSEVERIFY', 'cover')
    para('Evidence-driven security<br/>for Python, JavaScript and TypeScript', 'coverdeck')
    para('Project guide / current-stage edition', 'coverbody')
    STORY.append(Spacer(1, 27))
    para('A Meta-primary harness that inspects source, reproduces supported vulnerabilities in Docker, proposes repairs and requires independent verification before accepting them.', 'coverbody')
    STORY.append(Spacer(1, 18))
    cover_metrics = Table([[p('<font color="#FFFFFF"><b>99 tests</b><br/>Passed; no skips</font>', 'body'), p('<font color="#FFFFFF"><b>13 live Node targets</b><br/>8 verified repairs</font>', 'body'), p('<font color="#FFFFFF"><b>24 self-play scenarios</b><br/>Neutralized; 0 survivors</font>', 'body')]], colWidths=[WIDTH / 3] * 3)
    cover_metrics.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#23495B')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 13), ('TOPPADDING', (0, 0), (-1, -1), 13), ('BOTTOMPADDING', (0, 0), (-1, -1), 10)]))
    STORY.append(cover_metrics)
    HTML.append('<div class="cover-metrics"><div><strong>99 tests</strong><br/>Passed; no skips</div><div><strong>13 live Node targets</strong><br/>8 verified repairs</div><div><strong>24 self-play scenarios</strong><br/>Neutralized; 0 survivors</div></div>')
    STORY.append(Spacer(1, 24))
    para('<b>Current release</b><br/>Seven-phase verification for Python, JavaScript and TypeScript. Meta Spark and Wonder are mandatory; optional providers extend the review quorum.', 'coverbody')
    para('<b>Evidence snapshot</b><br/>Live Node corpus: 8 REMEDIATED, 4 FALSE_POSITIVE, 1 INCONCLUSIVE. Historical checks: 78 classifier cases and 25 remote acceptance groups. Scope and dates appear on pages 17-18.', 'coverbody')
    STORY.append(Spacer(1, 14))
    para(f'Application snapshot <b>{RELEASE[:7]}</b><br/>{DATE}', 'coverbody')

    page(1, 'Problem and core value', 'Candidate alerts need evidence before repair. Coding agents need containment when they inspect untrusted source or propose changes.', 'definition')
    sub('Two problems, one controlled workflow')
    para('Automated findings can consume maintainer time without proving a reachable bug. A model-generated patch can also change behavior or introduce a new weakness. Meanwhile, comments and literals can carry indirect instructions aimed at credential access, destructive actions or fabricated audit results.')
    table(['Area', 'Current stage'], [
        ('AgentWard', 'Source-aware ingress, proposed-tool-action policy, additive operator restrictions and checkpoint rewind. It protects the controlled workflow.'),
        ('MuseVerify', 'Isolated exploit reproduction, Meta-led repair, independent review, CodeShield, AST tripwires, self-play and functional regression.'),
        ('Core rule', 'Model advice can propose a repair. Only the orchestrator can accept it after all required evidence gates pass. Model judgments cannot waive deterministic controls.'),
        ('Evidence', 'Protected Docker traces and artifact hashes identify tested behavior. Static findings, fixture modes and live verified repairs stay distinct.'),
    ], [.20, .80])
    sub('Read this guide by task')
    table(['Task', 'Pages'], [
        ('Understand the architecture and supported inputs', '<link href="#architecture" color="#087E8B">3-5</link>'),
        ('Understand detection, policy and repair acceptance', '<link href="#ingress" color="#087E8B">6-9</link>'),
        ('Run and operate the system', '<link href="#providers" color="#087E8B">10-15</link>'),
        ('Review implementation, results and coverage limits', '<link href="#repository" color="#087E8B">16-20</link>'),
    ], [.80, .20])

    page(2, 'Architecture and trust boundaries', 'The workstation coordinates policy and verification. Submitted source and model output remain untrusted throughout the workflow.', 'architecture')
    STORY.append(Architecture())
    HTML.append('''<figure class="architecture"><figcaption>Execution and evidence boundaries</figcaption>
<div class="arch-row"><div>Operator + source</div><span aria-hidden="true">→</span><div>Orchestrator<br/>Policy, adapters and gates</div><span aria-hidden="true">↔</span><div>Meta primary<br/>Optional reviewers</div></div>
<p>Authenticated calls over loopback, SSH or a private tailnet</p>
<div class="arch-boundary"><strong>Verification node</strong><div class="arch-row"><div>Ingress service<br/>Classifier contract v2</div><div>Sandbox service<br/>Trusted tracer and bootstrap</div><span aria-hidden="true">→</span><div>Submitted payload<br/>Docker / UID 65534</div></div><p>Protected strace + source/harness hashes + language/runtime binding · Protocol v3</p></div>
<p>Required gates → accepted candidates, exact diffs, metrics and SARIF</p></figure>''')
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
        ('<b>5 / Regression</b>', 'Replay exploits, normal inputs and decoy probes.', 'Normal result preserved; exploit blocked; decoy triggers the logger, normal probe does not.'),
        ('<b>5.1 / Semantic Hunter</b>', 'Inspect related modules and semantic paths with Wonder-led analysis.', 'Static findings and unresolved assumptions remain visible, separate from runtime proof.'),
    ], [.22, .37, .41])
    sub('Concurrency and reporting')
    para('Phase 2 overlaps with graph construction and the initial policy baseline. The pipeline runs at most three containers concurrently. Passing that baseline cannot replace the later sandbox, patch or regression evidence.')
    para('A valid Phase 2 BENIGN result still requires Phase 3 policy review before FALSE_POSITIVE. For Node, static findings outside SQL/command probe coverage remain INCONCLUSIVE. Benign controls skip patch synthesis and later repair stages.', 'small')

    page(4, 'Supported languages and targets', 'Language support means a defined parser, execution harness and verification contract. It does not imply arbitrary project builds.', 'languages')
    table(['Language', 'Files', 'Supported verification scope'], [
        ('Python', '.py', 'Existing Python parsing, graph analysis and benchmark probes.'),
        ('JavaScript', '.js / .mjs / .cjs', 'Single-file Node ES/CommonJS modules with compatible exported SQL/command functions.'),
        ('TypeScript', '.ts / .mts / .cts', 'The same Node probes with erasable syntax. Original source executes in Node 24; scanning uses AST-based type erasure.'),
    ], [.19, .26, .55])
    sub('Node target contract')
    para('Node targets support named top-level functions and arrow functions in ES/CommonJS exports. All exports (maximum eight) must accept a single scalar SQL/command probe argument and return serializable results. Ambiguous or partial probe coverage is rejected.')
    para('Execution uses built-in dependencies such as node:sqlite and node:child_process. Every export must return successfully for <b>agentward_normal</b>; other business contracts need additional probes. Node always runs in Docker.')
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
    para('Short HTTP 429 capacity delays allow at most three identical client requests; exhausted retries remain unverified. All 13 current Node corpus files received unchanged-source ALLOW, with a maximum measured injection score of 0.017127.', 'small')

    page(6, 'Protected runtime evidence', 'The remote sandbox executes submitted code under a fixed, constrained runtime and keeps the evidence outside the payload’s control.', 'sandbox')
    table(['Boundary', 'Enforced control'], [
        ('Identity', 'Bearer authentication and bounded request schemas. Protocol v3 binds source/harness SHA-256, language, runtime and target filename.'),
        ('Privileges', 'Trusted root tracer and immutable bootstrap start first. Payload UID/GID: 65534; supplementary groups cleared; effective/permitted capabilities empty.'),
        ('Filesystem / network', 'No container network. Read-only root, source inputs and bootstrap; bounded 64 MiB workspace and 16 MiB temporary storage.'),
        ('Trace protection', 'Root-owned kernel trace in a POSIX-ACL-protected directory. Payloads cannot read, overwrite, unlink or replace host-backed evidence.'),
        ('Resources', '256 MiB memory/swap ceilings, CPU/PID limits and bounds on time, output, trace bytes and event counts. Overflow and timeout deny evidence and trigger cleanup.'),
        ('Runtime choice', 'Fixed python3/node allowlist. Python isolated startup; Node loader environment variables cleared. No arbitrary caller-selected interpreter.'),
    ], [.24, .76])
    sub('Conditions for accepted execution evidence')
    para('The client requires matching protocol and artifact identity plus complete protected traces and valid behavioral results. Missing traces, tampering, truncation, abnormal completion and unsupported ownership/ACL setup deny evidence. Docker failure cannot trigger production host execution.')
    callout('Deployment requirements', 'The supported node uses rootful Linux Docker without user-namespace remapping and an ACL-capable temporary filesystem. Rootless or remapped configurations are not validated.')
    para('Evidence is authenticated and hash-bound, not digitally signed. Selected syscalls and payload-produced probe lines cannot prove all possible behavior; the other acceptance gates remain necessary.', 'small')

    page(7, 'Runtime policy and workspace rewind', 'Phase 3 reviews the controlled tool workflow using the completed ingress and original sandbox evidence.', 'runtime')
    sub('Screen actions before authorizing continuation')
    para('agentward_stage3.py checks proposed action text for destructive commands, secret-exfiltration patterns and high-entropy strings, and tracks an estimated token budget. Known credential values are redacted from action text. Meta Spark leads concurrent policy and trajectory reviews with the selected independent auditors.')
    table(['Mechanism', 'Scope'], [
        ('Tool hook', 'enforce_permissions.py evaluates command-bearing JSON arguments for a PreToolUse integration. These are application hooks, not kernel syscall interception.'),
        ('Policy baseline', 'A checklist may be prepared during Phase 2. Final Phase 3 authorization requires the observed Docker evidence; preparation is not permission.'),
        ('Checkpoint / rewind', 'The guard copies top-level workspace files and writes SHA-256 manifest entries. trigger_rewind restores copies and removes new top-level files.'),
        ('Trajectory monitor', 'Drift, forbidden actions, missing review or stale policy can deny continuation. Detected violations can halt the session and trigger rewind.'),
    ], [.29, .71])
    sub('Add operator restrictions during a run')
    code('POST /api/steer\n{"constraint":"Forbid subprocess calls"}')
    para('Restrictions are additive and shared across dashboard batch workers. Each revision invalidates older in-flight approval. Recognized rules also have AST checks; broader natural-language rules depend on model review.')
    callout('What rewind does not promise', 'The checkpoint covers the disposable workspace, not arbitrary host effects, nested files or Git history. strace observes submitted code inside Docker. The tool hook must be integrated to mediate another agent’s actions.')

    page(8, 'How a repair earns acceptance', 'A proposed patch stays a candidate until independent checks agree with the observed behavior.', 'repairs')
    sub('Preserve the public contract')
    para('Patch checks preserve relevant function interfaces and sync/async behavior. Node checks also compare exported parameters and type signatures. Model-generated text cannot waive structural rules, scanning or current operator restrictions.')
    sub('Use independent evidence at each step')
    table(['Gate', 'What it contributes'], [
        ('Policy and review', 'Valid votes from the selected reviewers, bound to current additive operator constraints. Missing or malformed reviewer output denies approval.'),
        ('Static checks and CodeShield', 'Contract inspection, call/taint findings and scanner results. TypeScript is erased and reparsed for JavaScript rules; execution uses the original source.'),
        ('Structural tripwire', 'A reachable AST decoy equality guard calls a logger such as _tripwire(). A comment mentioning a canary cannot satisfy this check.'),
        ('Adversarial replay', 'Deterministic mutations and bounded scenarios run against original and candidate code. Original-code positive controls must reproduce the relevant behavior.'),
        ('Regression', 'The original exploit is blocked, tested normal results are preserved, and the tripwire fires only for decoy probes.'),
    ], [.27, .73])
    sub('Bounded self-play')
    para('Node tests three deterministic scenarios: syntax mutation, stored-value replay and URL-encoding replay. All three must be neutralized with valid evidence and successful original-code controls. Python also supports bounded model-proposed scenarios executed by deterministic harnesses.')
    para('Zero surviving mutations alone is insufficient. Unsupported or unproven scenarios are not counted as neutralized. Storage adapters test replay robustness, not arbitrary native persistence.', 'small')
    callout('Review the exact diff before integration', 'Accepted files and diffs go to <b>patches/&lt;run-id&gt;/</b>. Run <b>git apply --check</b> against the unchanged source before applying a diff; this is an integration step, not an automatic pipeline gate. Corpus acceptance applied all eight diffs in temporary directories and matched the saved patch hashes.')

    page(9, 'Providers and operator control', 'Meta remains mandatory for every live run. Optional providers add independent review when they pass pre-flight.', 'providers')
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
    sub('Optional high-end co-auditors')
    para('Anti-Gravity tries a supported selected model, then a deduplicated cascade: gemini-4-argon, claude-opus-5-5, claude-sonnet-5.5 and gemini-3.8. Quota failures are recorded during pre-flight. Custom BYOK supports compatible Responses and Chat Completions endpoints, including a /v1 base.')
    callout('Requested topology versus verified participation', 'all_three requests all three providers but excludes an unhealthy secondary with an explicit notice. It does not waive the required independent review. A selected reviewer failure cannot silently become approval.')

    page(10, 'Configure providers and node access', 'Use .env.example as the schema. Provider credentials stay on the workstation; the verification node uses its separate shared bearer token.', 'configuration')
    table(['Configuration', 'Purpose'], [
        ('META_API_KEY<br/>META_API_BASE_URL', 'Mandatory Meta key; default API base https://api.meta.ai/v1.'),
        ('ENSEMBLE_MODE', 'auto, all_three, meta_plus_agy, meta_plus_custom or meta_only.'),
        ('AGY_BIN<br/>AGY_SELECTED_MODEL', 'Optional CLI path and preferred supported model; default gemini-4-argon.'),
        ('CUSTOM_API_URL<br/>CUSTOM_API_KEY<br/>CUSTOM_MODEL_NAME', 'Compatible HTTP endpoint, BYOK credential and a model identifier supported by that endpoint.'),
        ('CUSTOM_REASONING_EFFORT<br/>CUSTOM_SERVICE_TIER', 'Optional model/endpoint features. Effort defaults to medium; service tier is empty unless configured.'),
        ('AI_TIMEOUT_S<br/>AGY_TIMEOUT_S', 'Task deadlines default to 120 / 180 seconds. Custom pre-flight has a five-second deadline.'),
        ('AGENTWARD_NODE_TOKEN', 'Same random token as the node configuration, at least 32 characters.'),
        ('AGENTWARD_INGRESS_URL<br/>AGENTWARD_SANDBOX_URL', 'Authenticated /scan-ingress and /execute endpoints over loopback, SSH or private tailnet access.'),
    ], [.45, .55])
    sub('Provider readiness is measured')
    para('GET /api/providers reports availability and topology without credential values. Meta pre-flight tests both native models. Custom requires HTTP 200 with nonempty, complete content; placeholder keys, auth errors, timeouts and missing endpoints exclude it.')
    callout('Configuration changes require fresh evidence', 'Use GET /api/providers?force_refresh=true after editing provider configuration. Restart the dashboard after node endpoint changes. Unknown model pricing remains unknown; token telemetry is not an invoice or a promised cost reduction.')

    page(11, 'Start a supported audit', 'Use the local dashboard or CLI after configuring the providers and authenticated verification-node endpoints.', 'quickstart')
    sub('1 / Prepare the workstation')
    code('python3 -m venv venv\n. venv/bin/activate\npython -m pip install -r requirements-dev.txt\ncp -n .env.example .env')
    para('Python 3.12+ is recommended. Populate the local .env with Meta credentials, the shared AGENTWARD_NODE_TOKEN, and AGENTWARD_INGRESS_URL / AGENTWARD_SANDBOX_URL. Keep secrets out of Git. The deployed private-node setup is described on the next page.', 'small')
    sub('2 / Start the dashboard')
    code('python -m uvicorn dashboard:app --host 127.0.0.1 \\\n  --port 8080 --ws-max-size 1024 --ws-max-queue 4')
    para('Open <link href="http://127.0.0.1:8080" color="#087E8B">http://127.0.0.1:8080</link>. Inspect the real provider pre-flight matrix, select an ensemble and choose a benchmark or a source path within the workspace. Retest credentials when configuration changes.', 'small')
    sub('3 / Run a known target')
    code('python main_pipeline.py benchmark_targets/cwe_78_cmd.js\npython main_pipeline.py benchmark_targets/cwe_89_sqli.ts\npython main_pipeline.py benchmark_targets/fp_node.mjs\npython main_pipeline.py benchmark_targets')
    para('The final command aggregates the supported Python and Node corpus. Single-file CLI runs replace the latest canonical report; a shared RunReport aggregates a custom subset. Inspect the exact diff and evidence before integration.', 'small')
    callout('A useful first comparison', '<b>cwe_78_cmd.js</b> and <b>cwe_89_sqli.ts</b> exercise vulnerable command/SQL paths. <b>fp_node.mjs</b> is the benign Node control. Passing ingress is expected for all three: the sandbox then distinguishes the tested runtime behavior.')
    para('Fixture-mode demonstrations have SIMULATED labels and cannot export verified SARIF fixes. Any permitted Python host execution is test-only; Node still requires Docker. See README.md for the explicit offline-demo commands.', 'small')

    page(12, 'Deploy to a supported Linux host', 'AWS Lightsail is optional. Use a local Linux host or a VM from another provider with the same Docker, filesystem and service-account requirements.', 'operations')
    table(['Requirement', 'Operational contract'], [
        ('Host and account', 'Rootful Linux Docker without user-namespace remapping; ACL-capable temporary filesystem; service account with Docker access.'),
        ('Bundled installer', 'Ubuntu/systemd recipe. USER_NAME is ubuntu; APP_DIR is /home/ubuntu/agentward-node. Adapt these settings for another account or distribution.'),
        ('Sandbox image', 'agentward-sandbox:multilang-v3. Recorded: Node 24.22.2 and Python 3.12.16. Dockerfile follows major/minor tags; rebuilds may change patch versions.'),
        ('Authentication', 'Random shared AGENTWARD_NODE_TOKEN in root-owned mode-0600 /etc/agentward/node.env and the ignored workstation .env.'),
    ], [.27, .73])
    sub('Install from the full checkout')
    para('Prepare Docker Engine, git, Python venv/pip, curl and ACL support first. On an Ubuntu node as its service account:', 'small')
    code('cd /home/ubuntu\ngit clone https://github.com/ephraimcrypto21/AgentWard-MuseVerify.git agentward-node\ncd agentward-node\nsudo docker build -t agentward-sandbox:multilang-v3 \\\n  -f security/Dockerfile.sandbox .\nsudo bash deploy_remote_services.sh')
    para('The script installs node requirements, provisions the pinned classifier and restarts both services on loopback ports 8000/8001. It preserves an existing token and reuses an existing image tag. For upgrades, update the checkout and explicitly rebuild the image before deploying.', 'small')
    callout('Coordinate versions and verify health', 'Keep the workstation, services, model contract and image compatible. Check both /health endpoints, then authenticated functional controls. A missing/short node token produces 503; incorrect authorization produces 401. Health alone does not establish live acceptance.')

    page(13, 'Connect the workstation and node', 'Choose SSH forwarding or persistent private Tailscale Serve. Services on the same Linux workstation can use loopback ports directly.', 'connectivity')
    sub('Option A / SSH forwarding')
    code('ssh -N -L 18000:127.0.0.1:8000 \\\n  -L 18001:127.0.0.1:8001 ubuntu@YOUR_HOST')
    para('Keep that connection open. Configure these workstation .env values and securely provision the same node token:', 'small')
    code('AGENTWARD_INGRESS_URL=http://127.0.0.1:18000/scan-ingress\nAGENTWARD_SANDBOX_URL=http://127.0.0.1:18001/execute')
    sub('Option B / Tailscale Serve within one tailnet')
    para('Install Tailscale on both hosts, join the same tailnet and run on the node:', 'small')
    code('tailscale ip -4\nsudo tailscale serve --bg --tcp=8000 tcp://127.0.0.1:8000\nsudo tailscale serve --bg --tcp=8001 tcp://127.0.0.1:8001\ntailscale serve status')
    para('Use the private address printed above or an enabled MagicDNS name:', 'small')
    code('AGENTWARD_INGRESS_URL=http://<NODE_IP>:8000/scan-ingress\nAGENTWARD_SANDBOX_URL=http://<NODE_IP>:8001/execute')
    callout('Preserve the private transport boundary', 'Tailscale carries HTTP inside its encrypted network. Restrict tailnet access and retain node bearer authentication; Serve is not public Funnel exposure. For a same-host setup use 127.0.0.1:8000/8001. Restart the dashboard after endpoint changes.')

    page(14, 'Dashboard, API and artifacts', 'The interface exposes progress and evidence without allowing advisory text to override a verified outcome.', 'interface')
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

    page(15, 'Codebase and skill integration', 'The implementation separates orchestration, model access, language rules, service security and evidence contracts.', 'repository')
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

    page(16, 'What has been verified', 'Application snapshot 2d52f29; evidence reviewed 1 November 2026. Each result has a specific date, mode and coverage.', 'validation')
    table(['Evidence set', 'Recorded result', 'What the result supports'], [
        ('Test suite<br/>1 November', '<b>99 passed</b><br/>Zero skips', 'Includes real Docker and corpus suites. Unit model fixtures do not constitute live-provider evidence.'),
        ('Live Node corpus<br/>1 November', '<b>13 targets</b><br/>8 / 4 / 1 outcomes', 'Real classifier, Meta Spark/Wonder and authenticated remote Docker: eight repairs, four false positives, one inconclusive weakness.'),
        ('Adapter and baseline checks', '<b>6 TS transforms</b><br/><b>17 exports</b>', 'All 13 targets parse and pass ingress unchanged. Six TypeScript sources erase/reparse/scan; every export returns normally in Docker.'),
        ('Classifier regression<br/>31 October', '<b>78 / 78</b><br/>45 benign + 33 malicious', 'Real pinned-model inference. Benign cases unchanged; malicious cases blocked or sanitized and rescanned. Development regression sets.'),
        ('Remote deployment<br/>31 October', '<b>25 groups</b>', 'Auth, language/hash binding, all seven extensions and isolation. Repair controls in this historical record used fixtures.'),
        ('Skill integrity', '<b>818 pinned trees</b>', 'Installed collection matches the source revision and full-tree hashes; this is not an audit of every procedure.'),
    ], [.27, .23, .50])
    sub('How to read the classifier result')
    para('The 78 cases include the reported false positives, normal object literals and exports, multilingual instructions, base64, long inputs, fake metadata and repeated documentation. These corpora were used during policy development. The result is regression evidence, not an accuracy estimate from an untouched holdout population.')
    callout('Current live evidence and historical checks', 'The latest corpus repairs were generated by live Meta Spark and independently reviewed by live Meta Wonder. Optional providers are covered by router tests, not claimed as participants in this live run. Historical fixture and browser records retain their original scope.')
    para('All reported counts come from the repository acceptance records and retained local evidence. They do not estimate industry-wide alert backlogs, model failure rates or general detection accuracy.', 'small')

    page(17, 'Live Node corpus: every outcome', 'All six Node extensions were checked. Detailed run IDs, source hashes, initial failures and accepted patch paths are in the dated corpus acceptance record.', 'corpus')
    table(['Target under benchmark_targets/', 'Final live outcome'], [
        ('cwe_78_cmd.js', 'REMEDIATED'),
        ('cwe_78_cmd_mjs.mjs', 'REMEDIATED'),
        ('cwe_78_cmd_alias.js', 'REMEDIATED'),
        ('cwe_78_cmd_ping.cts', 'REMEDIATED'),
        ('cwe_89_sqli.ts', 'REMEDIATED'),
        ('cwe_89_sqli_cjs.cts', 'REMEDIATED'),
        ('cwe_89_sqli_like.cjs', 'REMEDIATED'),
        ('cwe_89_sqli_login.mts', 'REMEDIATED'),
        ('fp_node.mjs', 'FALSE_POSITIVE'),
        ('fp_node_cjs.cjs', 'FALSE_POSITIVE'),
        ('fp_typescript_safe.ts', 'FALSE_POSITIVE'),
        ('fp_typescript_safe.mts', 'FALSE_POSITIVE'),
        ('cwe_338_weak_token.cjs', 'INCONCLUSIVE'),
    ], [.62, .38])
    para('Eight repairs neutralized 24 self-play scenarios with zero survivors. Saved patches preserve extensions and signatures, match protected regression hashes, and appear as eight verified SARIF fixes. All four benign controls made zero patch-synthesis or patch-verification calls.', 'small')
    para('The diagnostic CTS target now uses printf instead of network-dependent ping, preserving its command-injection defect. Two initial classifier-capacity failures remain archived; both targets passed reruns after bounded HTTP 429 retry handling.', 'small')
    callout('Retain the untested weakness', 'SQL probes do not verify Math.random token unpredictability. The weak-token case retains CWE-338, has no verified fix and remains INCONCLUSIVE. The combined SARIF invocation therefore reports executionSuccessful=false.')

    page(18, 'Interpreting results and limits', 'Use each outcome as evidence for the behavior and coverage actually checked. A completed run is not a formal proof of program safety.', 'limits')
    table(['Result or signal', 'Interpretation'], [
        ('Ingress ALLOW / SANITIZED', 'The source may continue to the remaining gates. This is not a vulnerability verdict.'),
        ('Ingress BLOCKED / UNVERIFIED', 'A classified attack was denied, or required evidence was absent/stale. The pipeline records an ingress-blocked outcome when live ingress cannot pass.'),
        ('REMEDIATED', 'Applicable gates and tested repair behavior passed with production evidence. Review the diff and stated assumptions before integrating it.'),
        ('FALSE_POSITIVE', 'Safe-path evidence and Phase 3 policy passed; patch synthesis was skipped. Node also requires no static finding outside its probe CWEs. This differs from an ingress classifier false positive.'),
        ('SIMULATED_*', 'Fixture-based demonstration. It cannot establish a production repair or export a verified SARIF fix.'),
        ('INCONCLUSIVE / rejected / failed', 'Evidence, policy, repair or regression requirements were not satisfied. Missing evidence is never an implicit pass.'),
    ], [.37, .63])
    sub('Coverage that remains bounded')
    para('<b>Detection:</b> unfamiliar instructions can evade the learned model; benign code can still be misclassified. New regressions should expand the corpus and trigger review of the pinned policy and model.')
    para('<b>Program analysis:</b> Python propagation is bounded; Node taint analysis is intraprocedural. Reflection, closures, dynamic dispatch, external libraries and Node cross-file flows need additional review. CodeShield coverage is narrower than a complete security audit.')
    para('<b>Runtime and operations:</b> selected probes and syscall traces cover observed behavior. The kernel, daemon, service, tracer and operator remain trusted. The shared token identifies an authorized workstation, not an individual user; provider data handling remains an operator decision.')
    callout('A useful next validation step', 'For a new production target, add representative functional probes and run the full live pipeline with fresh provider pre-flight. Expand adapters explicitly for new languages, application shapes and vulnerability families. These are extension directions, not shipped capabilities.')

    page(19, 'References and reproducibility', 'The PDF is a reviewed snapshot. Versioned repository documents and their implementation provide the detailed source of each claim.', 'references')
    table(['Reference', 'Use it for'], [
        ('<link href="' + REPO + '/blob/' + RELEASE + '/README.md" color="#087E8B">README.md</link>', 'Setup, provider configuration, API routes and complete verification commands.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/INGRESS_GUARD.md" color="#087E8B">docs/INGRESS_GUARD.md</link>', 'Classifier policy, model pin, regression evaluation and deployment.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/THREAT_MODEL.md" color="#087E8B">docs/THREAT_MODEL.md</link>', 'Trust boundaries, threat inventory and residual limits.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/LANGUAGES.md" color="#087E8B">docs/LANGUAGES.md</link>', 'Adapter contracts, syntax and execution limits.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/DEPLOYMENT_V3.md" color="#087E8B">docs/DEPLOYMENT_V3.md</link>', 'Recorded remote acceptance and coordinated rollback.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/CORPUS_ACCEPTANCE_2026-11-01.md" color="#087E8B">1 November corpus acceptance</link>', 'All 13 live results, 99-test record, retries and artifact verification.'),
        ('<link href="' + REPO + '/blob/' + RELEASE + '/docs/SKILLS.md" color="#087E8B">docs/SKILLS.md</link>', 'Community provenance, exact pin and applied skills.'),
    ], [.47, .53])
    para('Detailed live acceptance JSON remains in ignored local reports. The published documents summarize the evidence without embedding credentials, private endpoints or provider transcripts.', 'small')
    sub('Reproduce checks and rebuild this guide')
    code('AGENTWARD_TEST_DOCKER=1 \\\n  SANDBOX_IMAGE=agentward-sandbox:multilang-v3 \\\n  python -m unittest discover -v\npython -m pip check\npython -m pip install -r requirements-docs.txt\npython tools/build_project_guide.py \\\n  --output AgentWard_MuseVerify_Project_Guide.pdf')
    para('The generator writes the PDF and same-stem HTML companion from one reviewed source. Without --output it updates output/pdf/. No browser, live provider or node call is needed to build the guide.', 'small')
    para('README.md lists real Docker and live E2E checks. docs/INGRESS_GUARD.md lists all three classifier regression corpora; those commands need the provisioned node dependencies and pinned model. Rebuilding this guide does not revalidate a deployment.', 'small')
    para('<b>Terms:</b> AST: abstract syntax tree. BYOK: bring your own API key. CWE: Common Weakness Enumeration. SARIF: Static Analysis Results Interchange Format. Positive control: an original-code test that must reproduce the expected vulnerable behavior.', 'small')
    para(f'<b>Application revision:</b> {RELEASE}', 'small')


def html_document():
    """Self-contained, accessible companion using the same reviewed sections."""
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>AgentWard + MuseVerify — Project Guide</title>
<style>
:root{color-scheme:light;--navy:#112a3a;--ink:#203747;--teal:#087e8b;--light:#edf5f6;--rule:#d9e4e9}
*{box-sizing:border-box}body{margin:0;background:#eef2f5;color:var(--ink);font:16px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}
a{color:#08717d;text-underline-offset:3px}a:focus-visible{outline:3px solid #087e8b;outline-offset:4px}
main{max-width:980px;margin:36px auto}section{background:white;padding:42px 54px;margin-bottom:24px;scroll-margin-top:20px;border-top:4px solid var(--teal)}
h1,h2,h3{line-height:1.2;color:var(--navy)}h1{font-size:clamp(34px,7vw,60px);margin:12px 0 22px}h2{font-size:30px;margin:0 0 22px}h3{font-size:20px;margin:26px 0 12px;color:var(--teal)}
p{margin:0 0 16px}.small{font-size:14px}.kicker{font-size:12px;letter-spacing:1.5px;font-weight:700;color:var(--teal)}
section.cover{background:var(--navy);color:white;padding-top:60px;padding-bottom:60px}.cover h1{color:white}.coverdeck{font-size:25px;line-height:1.35;color:#bddfe5}.coverbody{max-width:740px}
.cover-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;background:#23495b;padding:22px;margin:30px 0}.cover-metrics strong{font-size:20px}
table{width:100%;border-collapse:collapse;font-size:14px;margin:18px 0 24px}th,td{padding:12px 14px;text-align:left;vertical-align:top;overflow-wrap:anywhere;border-bottom:1px solid var(--rule)}
th{background:var(--navy);color:white;font-weight:650}tbody tr:nth-child(odd){background:var(--light)}.table-scroll{overflow-x:auto}
aside{border-left:4px solid var(--teal);background:var(--light);padding:18px 22px;margin:24px 0}aside p{margin:8px 0 0}
pre{white-space:pre;overflow-x:auto;border:1px solid var(--rule);background:var(--light);padding:18px;font:13px/1.6 ui-monospace,DejaVu Sans Mono,monospace}
.architecture{margin:24px 0;padding:22px;border:1px solid var(--rule);background:#f8fafb;font-size:13px;text-align:center}.architecture figcaption{font-size:17px;font-weight:700;margin-bottom:22px}
.arch-row{display:flex;gap:12px;align-items:center;justify-content:center;margin:16px 0}.arch-row>div{flex:1;padding:14px 10px;border-radius:6px;background:var(--navy);color:white}.arch-row>span{color:var(--teal);font-size:24px}
.arch-boundary{border:2px dashed var(--teal);padding:16px;margin:20px 0}.architecture p{margin:14px 0}.arch-boundary>.arch-row>div{background:var(--light);color:var(--ink)}
nav{max-width:980px;margin:20px auto;padding:0 18px;display:flex;gap:20px;flex-wrap:wrap;font-size:14px}.edition{text-align:center;color:#536b79;font-size:13px;margin:24px 18px}
@media(max-width:650px){main{margin:0}section{padding:30px 22px}h2{font-size:25px}.cover-metrics{grid-template-columns:1fr}.arch-row{flex-direction:column}.arch-row>div{width:100%}.arch-row>span{transform:rotate(90deg)}th,td{padding:10px}pre{font-size:12px}}
@media print{@page{size:A4;margin:16mm}body{background:white;font-size:10pt}nav{display:none}main{margin:0;max-width:none}section{padding:0;margin:0;border:0;break-before:page}section:first-child{break-before:auto}section.cover{padding:24mm 12mm;print-color-adjust:exact}h2{font-size:22pt}h3{font-size:13pt}table{font-size:9pt}tr,aside,pre{break-inside:avoid}.table-scroll,pre{overflow:visible}pre{white-space:pre-wrap;font-size:8pt}.edition{font-size:8pt}}
</style></head><body><nav aria-label="Guide navigation"><a href="#definition">Overview</a><a href="#architecture">Architecture</a><a href="#quickstart">Quick start</a><a href="#corpus">Live results</a><a href="#references">Sources</a></nav><main>''' + '\n'.join(HTML) + '</section></main><p class="edition">Reviewed ' + escape(DATE) + ' · Application ' + RELEASE[:7] + ' · Generated by tools/build_project_guide.py</p></body></html>\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'output/pdf/AgentWard_MuseVerify_Project_Guide.pdf')
    args = parser.parse_args()
    if args.output.suffix.lower() != '.pdf':
        parser.error('--output must end in .pdf; the HTML companion uses the same stem')
    args.output = args.output.expanduser().absolute()
    html_output = args.output.with_suffix('.html')
    register_fonts()
    S.update(styles())
    STORY.clear()
    HTML.clear()
    rl_config.invariant = 1
    content()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=args.output.parent, suffix='.pdf', delete=False) as temp:
        temporary_output = Path(temp.name)
    temporary_html = None
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
        with NamedTemporaryFile('w', dir=args.output.parent, suffix='.html', delete=False, encoding='utf-8', newline='') as temp:
            temporary_html = Path(temp.name)
            temp.write(html_document())
        temporary_output.chmod(0o644)
        temporary_html.chmod(0o644)
        temporary_output.replace(args.output)
        temporary_html.replace(html_output)
    finally:
        temporary_output.unlink(missing_ok=True)
        if temporary_html:
            temporary_html.unlink(missing_ok=True)
    print(f'Wrote {args.output} ({doc.page} pages)')
    print(f'Wrote {html_output}')


if __name__ == '__main__':
    main()

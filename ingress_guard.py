"""Pinned, offline prompt-injection classifier and its evidence contract."""
import hashlib
import ast
import json
import math
from pathlib import Path
import tempfile

LOCK_PATH = Path(__file__).resolve().parent / 'security' / 'ingress-model.lock.json'
MODEL_LOCK = json.loads(LOCK_PATH.read_text())
BACKEND = 'injection_guard'
WINDOW_TOKENS = 512
OVERLAP_TOKENS = 128
RISK_THRESHOLD = 0.40
MAX_CONTEXT_CHARS = 1800
MAX_WINDOWS = 256
POLICY = {'version': 2, 'model': MODEL_LOCK, 'window_tokens': WINDOW_TOKENS,
          'overlap_tokens': OVERLAP_TOKENS, 'risk_threshold': RISK_THRESHOLD,
          'aggregation': 'maximum_injection_probability', 'input': 'complete_original_and_sanitized_source',
          'context': 'syntax-kinds-and-names-v1', 'max_context_chars': MAX_CONTEXT_CHARS,
          'max_windows': MAX_WINDOWS}
POLICY_SHA256 = hashlib.sha256(json.dumps(POLICY, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def contract():
    return {'version': POLICY['version'], 'policy_sha256': POLICY_SHA256,
            'model_id': MODEL_LOCK['model_id'], 'revision': MODEL_LOCK['revision']}


def verified_files(snapshot):
    """Verify bytes before any model/tokenizer files are parsed by Transformers."""
    paths = {}
    for name, expected in MODEL_LOCK['files_sha256'].items():
        path = Path(snapshot) / name
        with path.open('rb') as source:
            actual = hashlib.file_digest(source, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('Ingress model artifact hash mismatch: ' + name)
        paths[name] = path.resolve()
    return paths


def classification_input(source, language):
    """Add bounded parser facts; never remove, rewrite or assert safety of source."""
    if language == 'python':
        nodes = list(ast.walk(ast.parse(source)))
        names = [getattr(n, 'id', getattr(n, 'name', getattr(n, 'arg', getattr(n, 'attr', '')))) for n in nodes]
        kinds = [type(n).__name__ for n in nodes]
    elif language in ('javascript', 'typescript'):
        from ecmascript import parse, walk, text
        nodes = list(walk(parse(source, language)))
        names = [text(n) for n in nodes if n.type in ('identifier', 'property_identifier')]
        kinds = [n.type.replace('_', ' ') for n in nodes]
    else:
        raise ValueError('Unsupported classifier language')
    names = list(dict.fromkeys(n for n in names if n))[:16]
    kinds = list(dict.fromkeys(kinds))[:48]
    context = (language + ' syntax tree. Names: ' + ', '.join(n[:64] for n in names)
               + '. Node types: ' + ', '.join(kinds) + '.')[:MAX_CONTEXT_CHARS]
    return context + '\nSource:\n' + source



class SourceClassifier:
    def __init__(self, tokenizer, score_window):
        self.tokenizer = tokenizer
        self.score_window = score_window

    def classify(self, source, *, language):
        inputs = [classification_input(source, language)]
        risk, windows = 0.0, 0
        for text in inputs:
            encoded = self.tokenizer(text, truncation=True, max_length=WINDOW_TOKENS,
                                     stride=OVERLAP_TOKENS, return_overflowing_tokens=True,
                                     padding=False, return_attention_mask=True,
                                     return_token_type_ids=False)
            ids, masks = encoded['input_ids'], encoded['attention_mask']
            if not ids or len(ids) != len(masks):
                raise ValueError('Incomplete classifier windows')
            windows += len(ids)
            if windows > MAX_WINDOWS:
                raise ValueError('Classifier work limit exceeded; coverage incomplete')
            for tokens, mask in zip(ids, masks):
                if not tokens or len(tokens) > WINDOW_TOKENS or len(tokens) != len(mask):
                    raise ValueError('Invalid classifier window')
                scores = self.score_window(tokens, mask)
                if len(scores) != 2 or any(not math.isfinite(p) or not 0 <= p <= 1 for p in scores):
                    raise ValueError('Invalid classifier probabilities')
                if not math.isclose(sum(scores), 1.0, abs_tol=1e-5):
                    raise ValueError('Unnormalized classifier probabilities')
                risk = max(risk, scores[1])
        return {'benign': 1.0 - risk, 'injection': risk, 'windows': windows}


def load_classifier():
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

    snapshot = snapshot_download(MODEL_LOCK['model_id'], revision=MODEL_LOCK['revision'],
                                 allow_patterns=list(MODEL_LOCK['files_sha256']), local_files_only=True)
    files = verified_files(snapshot)
    # Only hash-verified files are visible to the loader, including optional files.
    with tempfile.TemporaryDirectory(prefix='agentward-model-') as directory:
        for name, path in files.items():
            (Path(directory) / name).symlink_to(path)
        config = AutoConfig.from_pretrained(directory, local_files_only=True, trust_remote_code=False)
        if [config.id2label[i] for i in range(config.num_labels)] != MODEL_LOCK['labels']:
            raise ValueError('Unexpected classifier label mapping')
        config.reference_compile = False
        tokenizer = AutoTokenizer.from_pretrained(directory, local_files_only=True, trust_remote_code=False)
        model = AutoModelForSequenceClassification.from_pretrained(
            directory, config=config, local_files_only=True, trust_remote_code=False,
            use_safetensors=True, attn_implementation='eager').eval()
    torch.set_num_threads(2)

    def score_window(tokens, mask):
        with torch.inference_mode():
            logits = model(input_ids=torch.tensor([tokens]), attention_mask=torch.tensor([mask])).logits
            return torch.softmax(logits, dim=-1)[0].tolist()

    return SourceClassifier(tokenizer, score_window)

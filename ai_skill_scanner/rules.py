"""Detection rule data: the Rule type, built-in rules, secret/lang patterns,
and scan tuning constants."""
import re
from typing import NamedTuple


class Rule(NamedTuple):
    """A compiled regex detection rule with its metadata."""
    regex: "re.Pattern[str]"
    id: str
    severity: str
    description: str

# Human-readable descriptions for each finding type, surfaced as SARIF rules.
RULE_DESCRIPTIONS: dict[str, str] = {
    "dangerous_code_execution": "Dangerous code execution primitive (eval/exec/subprocess/deserialization).",
    "suspicious_pattern": "Potential exfiltration, network callback, or prompt-injection indicator.",
    "high_entropy_obfuscation": "High-entropy string that may conceal an encoded payload.",
    "prompt_injection_risk": "Prompt-injection or exfiltration language in a skill definition.",
    "hardcoded_secret": "Hardcoded credential or private key.",
    "supply_chain_risk": "Dependency or build-step supply-chain risk.",
    "syntax_error": "File could not be parsed.",
    "read_error": "File could not be read.",
}

# SARIF level per scanner severity.
_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}

# Dangerous function targets detected via AST
DANGEROUS_FUNCS: set[str] = {
    "eval", "exec", "compile", "__import__",
    "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output",
    "os.system", "os.popen",
    "pickle.loads", "marshal.loads", "builtins.exec", "builtins.eval"
}

# Hosts that are common in documentation, packaging, and CI and are not
# meaningful exfiltration targets. Subdomains are allowed (see the lookahead).
BENIGN_HOSTS = (
    r"api\.openai\.com|api\.anthropic\.com|api\.groq\.com|api\.x\.ai|"
    r"github\.com|githubusercontent\.com|githubassets\.com|pypi\.org|"
    r"files\.pythonhosted\.org|python\.org|readthedocs\.io|shields\.io|"
    r"example\.(?:com|org|net)|w3\.org|json-schema\.org|schema\.org|"
    r"opensource\.org|apache\.org|mozilla\.org"
)

# Built-in detection rules (used when the signatures repo is unavailable or its
# pin does not verify). Each rule carries an id, severity, and description that
# flow through to findings, so results cite exactly which rule fired.
BUILTIN_RULES: list[Rule] = [
    Rule(re.compile(r'https?://(?!(?:[\w-]+\.)*(?:' + BENIGN_HOSTS + r')|localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\'`]{8,}', re.IGNORECASE),
         "BUILTIN-URL", "low", "Hardcoded URL to a non-allowlisted host that may receive exfiltrated data."),
    Rule(re.compile(r'(?:requests|urllib3?|httpx|http\.client|socket)\s*\.\s*(?:post|get|request|send|connect|create_connection)', re.IGNORECASE),
         "BUILTIN-NET", "medium", "Network call that could transmit secrets or agent state."),
    Rule(re.compile(r'(?:os\.environ(?:\.get)?|os\.getenv|getenv|environ)\s*[\[(]\s*["\']?[A-Za-z_][A-Za-z0-9_]*', re.IGNORECASE),
         "BUILTIN-ENV", "medium", "Environment-variable read (possible secret/credential access)."),
    Rule(re.compile(r'(?:ignore|disregard|override|forget|discard).*?(?:previous|all|system|prior|earlier|instructions|rules|policies|guidelines)', re.IGNORECASE),
         "BUILTIN-INJECT", "high", "Prompt-override phrasing attempting to bypass safety or force actions."),
    Rule(re.compile(r'(?:exfiltrat|leak|steal|exfil|beacon|callback|phonehome|upload|transmit).*?(?:data|secret|key|token|env|memory|context|prompt|user|agent|history)', re.IGNORECASE),
         "BUILTIN-EXFIL", "high", "Exfiltration / callback language targeting sensitive data."),
    Rule(re.compile(r'base64\.(?:b64encode|b64decode|standard_b64decode|urlsafe_b64decode)', re.IGNORECASE),
         "BUILTIN-B64", "medium", "Base64 encode/decode that may conceal a payload."),
    Rule(re.compile(r'marshal\.loads|zlib\.decompress|codecs\.decode.*rot', re.IGNORECASE),
         "BUILTIN-OBFUS", "high", "Obfuscated payload unpacking pattern (dropper / memory poisoning)."),
]

# Prose / configuration files. The generic regex and entropy heuristics are
# tuned for code; running them over documentation and packaging metadata (which
# naturally discuss and contain these tokens) is the dominant false-positive
# source. Such files still get the dedicated prompt-injection check below.
# .txt is intentionally NOT here: it is scanned as code, since a plain-text file
# in a skill repo is a plausible payload carrier (and requirements.txt needs it).
PROSE_SUFFIXES: set[str] = {".md", ".markdown", ".rst", ".toml", ".cfg", ".ini"}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

# Resource limits for scanning untrusted input. The scanner is meant to run on
# hostile repositories, so file size and per-line regex work are bounded to
# prevent memory exhaustion and pathological regex backtracking (ReDoS).
MAX_FILE_BYTES = 2 * 1024 * 1024   # skip files larger than 2 MiB
MAX_SCAN_LINE = 2000               # skip regex on longer (minified/data) lines

# High-confidence secret patterns (provider tokens + private keys). Matched on
# every scanned file; the matched value is redacted in the finding snippet so
# the scanner never writes a discovered secret into its own report.
_SECRET_RULES: list[Rule] = [
    Rule(re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "SEC-AWS-KEY", "high", "Hardcoded AWS access key id."),
    Rule(re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "SEC-GITHUB-TOKEN", "high", "Hardcoded GitHub token."),
    Rule(re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "SEC-GITHUB-PAT", "high", "Hardcoded GitHub fine-grained token."),
    Rule(re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "SEC-SLACK-TOKEN", "high", "Hardcoded Slack token."),
    Rule(re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "SEC-GOOGLE-KEY", "high", "Hardcoded Google API key."),
    Rule(re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "SEC-OPENAI-KEY", "high", "Hardcoded OpenAI-style API key."),
    Rule(re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "SEC-PRIVATE-KEY", "high", "Embedded private key."),
]

# Lower-confidence generic credential assignment (code files only).
_SECRET_ASSIGN = re.compile(
    r"""(?ix)
    (?:api[_-]?key|secret|token|passwd|password|access[_-]?key|private[_-]?key)
    \s*[:=]\s*["'][^"']{8,}["']
    """
)

# Dangerous constructs for shell and JavaScript/TypeScript, applied to those
# code files in addition to the generic rules.
_LANG_RULES: list[Rule] = [
    Rule(re.compile(r"""require\(\s*["']child_process|(?<![\w.])child_process\b"""),
         "JS-CHILD-PROC", "high", "Node child_process use (command execution)."),
    Rule(re.compile(r"(?<![\w.])(?:eval|Function)\s*\("),
         "JS-EVAL", "high", "Dynamic code execution (eval/Function)."),
    Rule(re.compile(r"\b(?:execSync|spawnSync|execFile|execFileSync)\s*\(|(?<![\w.])(?:exec|spawn)\s*\("),
         "JS-EXEC", "high", "Node exec/spawn (command execution)."),
    Rule(re.compile(r"(?:curl|wget)\s[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", re.IGNORECASE),
         "SH-PIPE-SHELL", "high", "Piping a download straight into a shell."),
    Rule(re.compile(r"base64\s+-d[^\n|]*\|\s*(?:sh|bash)\b", re.IGNORECASE),
         "SH-B64-SHELL", "high", "Decoding base64 straight into a shell."),
    Rule(re.compile(r"(?<![\w.])eval\s+[\"']?\$"),
         "SH-EVAL", "high", "Shell eval of a variable."),
]
_CODE_LANG_SUFFIXES = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".sh", ".bash"}

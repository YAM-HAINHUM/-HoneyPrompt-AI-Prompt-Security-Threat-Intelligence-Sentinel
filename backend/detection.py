import os
import re
from pathlib import Path

try:
    import joblib
except ImportError:
    joblib = None


MODEL_PATH = Path(__file__).resolve().parent / "models" / "prompt_classifier.joblib"
_MODEL_ARTIFACT = None


def load_threat_model(model_path: str | os.PathLike | None = None) -> bool:
    """Load the trained classifier once during backend startup."""
    global _MODEL_ARTIFACT
    path = Path(model_path) if model_path else MODEL_PATH
    if joblib is None or not path.is_file():
        _MODEL_ARTIFACT = None
        return False
    try:
        _MODEL_ARTIFACT = joblib.load(path)
        return True
    except (OSError, ValueError, ImportError, EOFError):
        _MODEL_ARTIFACT = None
        return False


def model_probability(text: str) -> float | None:
    """Return the model's calibrated probability that a prompt is malicious."""
    if _MODEL_ARTIFACT is None:
        return None
    model = _MODEL_ARTIFACT.get("model")
    if model is None:
        return None
    try:
        probabilities = model.predict_proba([text])[0]
        malicious_index = list(model.classes_).index("MALICIOUS")
        return float(probabilities[malicious_index])
    except (AttributeError, IndexError, KeyError, ValueError):
        return None


def _ml_threat_type(text: str) -> str | None:
    """Use the attack-type sub-classifier to identify the threat category."""
    if _MODEL_ARTIFACT is None:
        return None
    at_model = _MODEL_ARTIFACT.get("attack_type_model")
    at_map = _MODEL_ARTIFACT.get("attack_type_map", {})
    if at_model is None:
        return None
    try:
        raw = at_model.predict([text])[0]
        mapped = at_map.get(str(raw).casefold(), None)
        return mapped if mapped and mapped != "None" else None
    except Exception:
        return None


def _fuse_confidence(rule_confidence: float, malicious_probability: float | None) -> float:
    if malicious_probability is None:
        return rule_confidence
    return round(1 - (1 - rule_confidence) * (1 - malicious_probability), 3)

# ---------------------------------------------------------------------------
# THREAT DEFINITIONS
# Each entry: patterns (regex), semantic_hints (substring phrases for Layer 2),
# risk (base score), threat_type, severity
# ---------------------------------------------------------------------------
THREAT_RULES = [
    {
        "id": "compliance_trap",
        "threat_type": "Honeypot Trigger",
        "severity": "CRITICAL",
        "risk": 100,
        "patterns": [r"99[\s\-]*delta", r"admin\s+override"],
        "semantic": [],
    },
    {
        "id": "data_trap",
        "threat_type": "Confidential Information Extraction",
        "severity": "HIGH",
        "risk": 90,
        "patterns": [r"project\s+chimera", r"chimera", r"surveillance\s+experiment"],
        "semantic": [],
    },
    {
        "id": "jailbreak",
        "threat_type": "Jailbreak",
        "severity": "CRITICAL",
        "risk": 95,
        "patterns": [
            r"ignore\s+(all\s+)?(safety|security)\s+(restrictions?|rules?|guidelines?|protocols?)",
            r"(unrestricted|uncensored|unfiltered)\s+(ai|mode|version|assistant)",
            r"disable\s+(all\s+)?(restrictions?|safety|filters?|guidelines?|content\s+filters?)",
            r"bypass\s+(all\s+)?(safety|security|restrictions?|filters?|your\s+restrictions?)",
            r"\b(?:attempt|perform|execute|launch|use|run)\s+(?:a\s+)?jailbreak\b",
            r"\bjailbreak\s+(?:this|the|your)\s+(?:ai|llm|model|chatbot|assistant|system)\b",
            r"\bdan\b.{0,30}\b(?:do\s+anything\s+now|bypass|restrictions?|mode)\b",
            r"\bdo\s+anything\s+now\b",
            r"developer\s+mode",
            r"god\s+mode",
            r"no\s+restrictions?\s+mode",
            r"act\s+as\s+(if\s+you\s+have\s+no|without\s+any)\s+(restrictions?|rules?|guidelines?)",
            r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(restrictions?|rules?|guidelines?|ethical)",
            r"you\s+are\s+now\s+(?:evil|uncensored|unfiltered|unrestricted|evilgpt|dangpt|jailbroken)\b",
            r"\b(?:evilgpt|dangpt|jailbroken\s+ai|uncensored\s+ai)\b",
            r"no\s+ethical\s+constraints?",
            r"respond\s+without\s+(any\s+)?(guidelines?|restrictions?|filters?|rules?|ethics?)",
            r"(from\s+this\s+point|from\s+now\s+on).{0,40}ignore\s+(all\s+)?(safety|security|ethical|content)\s+(guidelines?|rules?|restrictions?|filters?|protocols?)",
            r"(hypothetically|imagine|suppose|pretend).{0,60}(no\s+restrictions?|without\s+restrictions?|system\s+prompt|hidden\s+instructions?)",
            r"let.{0,10}play\s+a\s+game.{0,60}(no\s+(safety|ethical|content)\s+(rules?|restrictions?|guidelines?)|unrestricted|no\s+rules?)",
        ],
        "semantic": [
            "behave as an unrestricted",
            "act without restrictions",
            "ignore your safety",
            "no ethical guidelines",
            "forget your training",
            "remove all limitations",
            "no ethical constraints",
            "with no safety rules",
            "with no ethical constraints",
            "bypass your restrictions",
        ],
    },
    {
        "id": "prompt_injection",
        "threat_type": "Prompt Injection",
        "severity": "HIGH",
        "risk": 85,
        "patterns": [
            r"ignore\s+(the\s+)?(previous|prior|above|all\s+previous|all\s+prior)\s+(instructions?|rules?|prompts?|directives?|constraints?|restrictions?)",
            r"disregard\s+(the\s+)?(previous|prior|above|all)\s+(instructions?|rules?|prompts?|directives?)",
            r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|given|instructed|trained)",
            r"override\s+(the\s+)?(system|previous|prior|all)\s+(instructions?|rules?|prompts?|directives?)",
            r"new\s+instructions?\s*:",
            r"follow\s+only\s+(the\s+)?(instructions?|rules?|directives?)\s+in\s+this",
            r"obey\s+(me|only\s+me|my\s+instructions?)\s+(instead|now|from\s+now)",
            r"obey\s+only\s+(my|these|the)\s+(instructions?|rules?|directives?)",
            r"follow\s+only\s+(my|these|the)\s+(instructions?|rules?|directives?)",
            r"from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+(ignore|forget|disregard)",
        ],
        "semantic": [
            "forget what you were told",
            "ignore your previous",
            "disregard your instructions",
            "override your instructions",
            "follow my instructions instead",
            "obey me instead",
            "new directive",
        ],
    },
    {
        "id": "system_prompt_extraction",
        "threat_type": "System Prompt Extraction",
        "severity": "HIGH",
        "risk": 88,
        "patterns": [
            r"(reveal|show|tell\s+me|display|print|output|expose|share|give\s+me)\s+(the\s+)?(exact\s+)?(hidden|secret|confidential|internal|original|full|complete|actual|real)?\s*(system\s+prompt|system\s+instructions?|initial\s+prompt|base\s+prompt|core\s+instructions?|hidden\s+instructions?|private\s+instructions?)",
            r"what\s+(is|are)\s+(your|the)\s+(system\s+prompt|hidden\s+instructions?|secret\s+instructions?|initial\s+instructions?|core\s+instructions?|confidential\s+instructions?)",
            r"(show|reveal|tell\s+me|display)\s+(your|the)\s+(system|hidden|secret|confidential|internal)\s+(prompt|instructions?|rules?|directives?|configuration|config)",
            r"(copy|paste|repeat|reproduce|output)\s+(your|the)\s+(system\s+prompt|instructions?|initial\s+prompt)",
            r"what\s+(?:does|do)\s+(?:your|the)\s+(?:hidden|secret|system|internal)\s+(?:prompt|instructions?|rules?)\s+(?:say|contain|include)",
        ],
        "semantic": [
            "hidden instructions that control",
            "private instructions that govern",
            "secret instructions you follow",
            "confidential instructions you were given",
            "what instructions control your",
            "reveal your hidden",
            "show me your system",
            "tell me your instructions",
            "what were you told to do",
            "what rules govern your",
        ],
    },
    {
        "id": "role_manipulation",
        "threat_type": "Role Manipulation",
        "severity": "HIGH",
        "risk": 82,
        "patterns": [
            r"you\s+are\s+now\s+(the\s+)?(system\s+administrator|admin|root|superuser|god|master|owner|developer|creator)",
            r"pretend\s+(to\s+be|you\s+are)\s+(the\s+)?(system\s+administrator|admin|root|superuser|god|master|owner|developer|creator)",
            r"act\s+as\s+(the\s+)?(system\s+administrator|admin|root|superuser|god|master|owner|developer|creator)",
            r"switch\s+(to|into)\s+(admin|administrator|root|superuser|developer|god)\s+mode",
            r"enter\s+(admin|administrator|root|superuser|developer|god)\s+mode",
        ],
        "semantic": [
            "you are now the system administrator",
            "act as the administrator",
            "pretend to be the system",
            "switch to admin mode",
            "you are now an unrestricted",
        ],
    },
    {
        "id": "privilege_escalation",
        "threat_type": "Privilege Escalation",
        "severity": "HIGH",
        "risk": 85,
        "patterns": [
            r"(grant|give\s+me|i\s+need|request)\s+(admin|administrator|root|superuser|elevated|full)\s+(access|privileges?|permissions?|rights?)",
            r"(reveal|show|access|unlock)\s+(all\s+)?(restricted|classified|confidential|protected|private|sensitive)\s+(information|data|files?|documents?|records?)",
            r"(you\s+are\s+now|i\s+am\s+now)\s+(authorized|permitted|allowed)\s+to\s+(access|view|see|read)",
        ],
        "semantic": [
            "reveal all restricted information",
            "access restricted data",
            "grant me admin access",
            "unlock all information",
            "show me classified",
        ],
    },
    {
        "id": "data_exfiltration",
        "threat_type": "Data Exfiltration",
        "severity": "HIGH",
        "risk": 80,
        "patterns": [
            r"(send|transmit|export|exfiltrate|leak|dump)\s+(all\s+)?(data|information|records?|files?|documents?|logs?)\s+(to|via|through|using)",
            r"(extract|steal|copy|download)\s+(all\s+)?(sensitive|confidential|private|internal|classified)\s+(data|information|records?|files?)",
            r"dump\s+(the\s+)?(entire\s+)?(database|db|user\s+data|all\s+records?)",
            r"extract\s+(all\s+)?(sensitive|user|customer|private|confidential|internal)\s+(information|data|records?)",
            r"what\s+is\s+stored\s+in\s+your\s+(conversation|chat)\s+history\s+for\s+(other\s+)?users?",
            r"(show|reveal|access|get)\s+(me\s+)?(other\s+users?|other\s+people.{0,10})(conversation|chat|message|history|data)",
        ],
        "semantic": [
            "send all data to",
            "extract sensitive information",
            "leak internal data",
            "dump all records",
            "dump the entire database",
            "extract all sensitive",
            "stored in your conversation history for other users",
        ],
    },
    {
        "id": "security_bypass",
        "threat_type": "Security Policy Bypass",
        "severity": "MEDIUM",
        "risk": 75,
        "patterns": [
            r"(bypass|circumvent|evade|avoid|skip)\s+(the\s+)?(security|safety|content|moderation|filter|policy|restriction|guideline)",
            r"(how\s+to|ways?\s+to|method\s+to)\s+(bypass|circumvent|evade|hack|break)\s+(the\s+)?(ai|llm|chatbot|system|security|safety)",
        ],
        "semantic": [
            "bypass the security",
            "circumvent the safety",
            "evade the filter",
            "get around the restrictions",
        ],
    },
    {
        "id": "obfuscated_payload",
        "threat_type": "Prompt Injection",
        "severity": "HIGH",
        "risk": 88,
        "patterns": [
            r"(decode|run|execute|carry\s+out|perform).{0,30}(base64|payload|encoded\s+command|hex\s+string)",
            r"(run|execute|carry\s+out).{0,30}(command|instruction).{0,30}(encoded|spelled|phonetic|pig\s+latin|rot13|base64)",
            r"(spelled\s+out|nato\s+phonetic|phonetic\s+alphabet).{0,60}(command|instruction|execute|run|carry\s+out)",
            r"(translate|convert|encode|decode).{0,40}(system\s+prompt|instructions?|hidden).{0,40}(pig\s+latin|base64|rot13|phonetic|encoded)",
            r"[a-zA-Z0-9+/]{20,}={0,2}\s*(and\s+)?(carry\s+out|execute|run|perform|decode\s+and)",
            r"i\s+g\s+n\s+o\s+r\s+e",
        ],
        "semantic": [
            "decode this payload and carry out",
            "run this base64",
            "execute the command spelled out",
            "translate your system prompt into pig latin",
            "nato phonetic first letters",
        ],
    },
]

# ---------------------------------------------------------------------------
# EDUCATIONAL / DEFENSIVE CONTEXT SIGNALS
# If these appear alongside sensitive words, reduce false positives.
# ---------------------------------------------------------------------------
_EDUCATIONAL_CONTEXT_PATTERNS = [
    r"\b(?:how\s+(?:does|do|can\s+i\s+learn|can\s+i\s+study)|what\s+is|explain|learn\s+about|study|research|course|tutorial|book|article|paper|thesis|academic|university|college|class|lecture|exam|quiz|homework|assignment|project|report|essay|presentation|demo|example|sample|practice|exercise|lab|workshop|conference|seminar|webinar|podcast|video|blog|documentation|wiki|faq|guide|overview|introduction|basics|fundamentals|concept|theory|history|background|context|definition|meaning|difference\s+between|compare|contrast|pros\s+and\s+cons|advantages|disadvantages|use\s+case|real.world|scenario|case\s+study)\b",
    r"\b(?:help\s+(?:me\s+)?understand|want\s+to\s+understand|trying\s+to\s+understand|understand\s+(?:the|how|why|what))\b",
    r"\b(?:cybersecurity|information\s+security|infosec|penetration\s+testing|pen\s+test|ethical\s+hacking|bug\s+bounty|ctf|capture\s+the\s+flag|red\s+team|blue\s+team|purple\s+team|security\s+research|vulnerability\s+research|threat\s+modeling|risk\s+assessment|security\s+audit|compliance|nist|owasp|mitre|att&ck|cve|cwe|cvss)\b",
    r"\b(?:defend|protect|prevent|mitigate|detect|monitor|analyze|investigate|respond\s+to|patch|fix|remediate|harden|secure|safeguard|audit|review|assess|test|scan|probe|identify|discover|report|disclose|responsible\s+disclosure)\b",
    r"\b(?:for\s+(?:educational|learning|research|academic|study|training|awareness|demonstration|testing|practice|fun|a\s+class|a\s+course|a\s+project|a\s+report|a\s+paper|a\s+presentation|a\s+demo|a\s+ctf|a\s+lab|a\s+workshop|a\s+seminar|a\s+conference|a\s+book|a\s+tutorial|a\s+guide|a\s+blog|a\s+video|a\s+podcast|a\s+article|a\s+thesis|a\s+assignment|a\s+homework|a\s+exam|a\s+quiz|a\s+exercise|a\s+scenario|a\s+case\s+study|a\s+use\s+case|a\s+example|a\s+sample|a\s+overview|a\s+introduction|a\s+background|a\s+context|a\s+definition|a\s+concept|a\s+theory|a\s+history|a\s+comparison|a\s+contrast|a\s+analysis|a\s+review|a\s+assessment|a\s+audit|a\s+test|a\s+scan|a\s+probe|a\s+identification|a\s+discovery|a\s+report|a\s+disclosure))\b",
]


def _is_educational_context(text_lower: str) -> bool:
    """Return True if the text contains clear educational/defensive/research signals, and no overt illegal intent."""
    if re.search(r"\b(?:illegally?|unlawfully?|without\s+(?:permission|authorization|consent|his\s+knowledge|him\s+knowing|her\s+knowing|their\s+knowing|getting\s+caught|being\s+detected)|unauthorized)\b", text_lower):
        return False
    return any(re.search(p, text_lower) for p in _EDUCATIONAL_CONTEXT_PATTERNS)


# Semantic intent matching requires both an action and a sensitive target. This
# catches paraphrases without treating an isolated word such as "password" as
# malicious.
SEMANTIC_INTENT_RULES = [
    {
        "id": "system_prompt_extraction",
        "threat_type": "System Prompt Extraction",
        "severity": "HIGH",
        "risk": 92,
        "intent": [
            r"\b(?:reveal|show\s+me(?!\s+how\b)|tell\s+me\s+(?!how\b)|display|print|output|repeat|recite|copy)\b",
            r"\bwhat\s+(?:is|are|does|do)\s+(?:your|the|its)\b",
        ],
        "target": [
            r"\b(?:(?:hidden|secret|confidential|internal|system|initial|initialization|base|private|developer)\s+)+(?:system\s+)?(?:prompt|instructions?|directives?|configuration|rules?)\b",
        ],
        "reason": "The prompt requests hidden system or developer instructions.",
    },
    {
        "id": "prompt_injection",
        "threat_type": "Prompt Injection",
        "severity": "HIGH",
        "risk": 90,
        "intent": [
            r"\b(?:ignore|disregard|override|replace|forget|set\s+aside|obey\s+only|follow\s+only)\b",
        ],
        "target": [
            r"\b(?:(?:all|any|the|your|previous|prior|system|developer|governing|current|existing|my)\s+)*(?:instructions?|directives?|rules?|policies|restrictions?|guidelines?)\b",
        ],
        "reason": "The prompt attempts to replace, ignore, or override governing instructions.",
    },
    {
        "id": "credential_extraction",
        "threat_type": "Credential Extraction",
        "severity": "CRITICAL",
        "risk": 100,
        "intent": [
            r"\b(?:give\s+me|show\s+me(?!\s+how\b)|tell\s+me\s+(?!how\b)|reveal|disclose|expose|print|output|provide|share|send|fetch|retrieve|obtain|steal|extract)\b",
            r"\b(?:tell|show)\s+me\s+how\s+to\s+(?:get|find|retrieve|access|obtain|steal|extract)\b",
            r"\bhow\s+(?:can|could|would|do)\s+i\s+(?:get|find|retrieve|access|obtain|steal|extract)\b",
            r"\bwhat\s+(?:is|are)\s+(?:the|your|system|admin)\b",
        ],
        "target": [
            r"\b(?:(?:system|admin|administrator|root|database|account|login|api|private|access)\s+)*(?:passwords?|passcodes?|credentials?|api\s+keys?|tokens?|secrets?|private\s+keys?)\b",
        ],
        "exclude": [
            r"\b(?:tips?|advice|best\s+practices?|create|generate|change|reset|rotate|store|secure|protect|choose|manage)\b.{0,45}\b(?:passwords?|credentials?|api\s+keys?|tokens?)\b",
        ],
        "reason": "The prompt requests credentials or restricted authentication information.",
    },
    {
        "id": "data_exfiltration",
        "threat_type": "Data Exfiltration",
        "severity": "HIGH",
        "risk": 92,
        "intent": [
            r"\b(?:export|email|send|upload|dump|copy|transmit|leak|exfiltrate|forward|extract|download)\b",
        ],
        "target": [
            r"\b(?:(?:all|user|customer|employee|account|private|confidential|sensitive|internal|classified|database)\s+)+(?:user\s+|customer\s+)?(?:data|records?|files?|documents?|logs?|information|database|tables?)\b",
            r"\b(?:all\s+)?(?:user|customer|employee|account)\s+(?:data|records?|files?|documents?|database|tables?)\b",
        ],
        "destination": [r"\b(?:to|via|through|into|my\s+(?:email|account|server)|external)\b"],
        "reason": "The prompt attempts to transfer or expose private records to a destination.",
    },
    {
        "id": "harmful_attack_request",
        "threat_type": "Harmful Request",
        "severity": "CRITICAL",
        "risk": 100,
        "intent": [
            r"\b(?:how\s+(?:(?:can|could|would)\s+)?(?:i|someone|a\s+person)|help\s+me|teach\s+me\s+to|show\s+me\s+how\s+to|give\s+me\s+(?:steps|instructions)|(?:steps|instructions|methods?|plans?|strategies|ways?)\s+to|i\s+(?:want|need|plan|intend)\s+to|write|build|create|deploy|make)\b",
            r"\b(?:i\s+(?:want|need|plan|intend|am\s+going)\s+to\s+(?:break\s+into|get\s+into|access|infiltrate|compromise|hack|attack))\b",
            r"\b(?:break\s+into|get\s+(?:unauthorized|illegal)\s+access|access\s+without\s+(?:permission|authorization))\b",
        ],
        "target": [
            r"\b(?:attack|hack|breach|compromise|infiltrate|infect|exploit|phish|disrupt|take\s+down)\b.{0,60}\b(?:organization|company|business|network|server|website|account|computer|person|users?|system)\b",
            r"\b(?:attack|hack|breach|infiltrate|exploit)\b.{0,60}\b(?:friend'?s?|someone'?s?|his|her|their)\s+(?:system|computer|phone|account|network|device|laptop|pc)\b",
            r"\b(?:hack|attack|breach)\s+(?:a\s+|the\s+)?(?:system|network|server|website|account)\s+illegally\b",
            r"\b(?:illegally|unauthorized)\s+(?:hack|attack|breach)\b",
            r"\b(?:ransomware|keylogger|credential\s+stealer|malware|exploit\s+kit|botnet|bomb|explosive|poison)\b",
            r"\bwrite\s+code\s+to\s+exploit\b",
            r"\b(?:sql\s+injection|xss|cross.site\s+scripting|buffer\s+overflow|remote\s+code\s+execution)\b.{0,40}\b(?:exploit|attack|vulnerability|payload|code)\b",
            r"\b(?:company|organization|business|network|server|website|system|account).{0,40}\b(?:without\s+(?:permission|authorization|their\s+knowledge)|illegally|unauthorized)\b",
            r"\b(?:break\s+into|get\s+into).{0,40}\b(?:company|organization|server|network|system|account|website|database)\b",
        ],
        "exclude": [
            r"\b(?:defend|protect|prevent|mitigate|detect|recognize|monitor|analyze|investigate|respond\s+to)\b.{0,60}\b(?:attack|hack|breach|compromise|infiltrate|infect|exploit|phish|ransomware|keylogger|malware|botnet)\b",
            r"\b(?:detector|detection|defense|defence|scanner|monitoring|analysis)\b.{0,45}\b(?:attack|hack|breach|exploit|phish|ransomware|keylogger|malware|botnet)\b",
            r"\b(?:attack|hack|breach|exploit|phish|ransomware|keylogger|malware|botnet)\b.{0,45}\b(?:detector|detection|defense|defence|scanner|monitoring|analysis|prevention)\b",
        ],
        "reason": "The prompt requests instructions or tools for attacking people, systems, or organizations.",
    },
]

# Suspicious probing — lower risk, not malicious
SUSPICIOUS_RULES = [
    {
        "id": "ambiguous_attack_query",
        "threat_type": "Unauthorized Access Probing",
        "severity": "MEDIUM",
        "risk": 55,
        "patterns": [
            r"\b(?:can|could|is\s+it\s+possible\s+to|how\s+easy\s+is\s+it\s+to)\s+(?:i\s+|someone\s+|a\s+person\s+)?(?:attack|hack|breach|infiltrate|break\s+into)\s+(?:a\s+|any\s+|the\s+)?(?:system|computer|server|network|website|database|account)",
            r"\b(?:attack|hack|breach)\s+(?:a\s+|any\s+)?(?:system|computer|server|network)\s+(?:easily|quick(?:ly)?|simple|simply|fast)\b",
            r"\b(?:is\s+it\s+easy\s+to|how\s+hard\s+is\s+it\s+to)\s+(?:attack|hack|breach)\b",
            r"\b(?:can\s+i\s+hack|can\s+i\s+attack|can\s+we\s+hack)\b",
        ],
        "semantic": [
            "can i attack a system easily",
            "can i attack a system",
            "can i attack easily",
            "is it easy to hack",
            "how to attack easily",
        ],
    },
    {
        "id": "suspicious_probing",
        "threat_type": "Security Probing",
        "severity": "LOW",
        "risk": 45,
        "patterns": [
            r"what\s+instructions?\s+are\s+you\s+following",
            r"what\s+(rules?|guidelines?|directives?)\s+(do\s+you|are\s+you)\s+(follow|following|using|given)",
            r"what\s+(instructions?|rules?|guidelines?|directives?|constraints?)\s+(do\s+you|are\s+you)\s+(follow|following|use|using|obey)",
            r"how\s+(are\s+you|were\s+you)\s+(programmed|configured|set\s+up|trained|instructed)",
            r"(?:how|where|when)\s+(?:are|were)\s+you\s+(programmed|configured|set\s+up|trained|instructed)",
            r"(tell\s+me|explain)\s+(about\s+)?(your|the)\s+(programming|configuration|setup|training|instructions?)",
            r"(?:can|could)\s+you\s+(?:describe|explain|outline)\s+(your|the)\s+(response\s+)?(rules?|guidelines?|configuration|capabilities|limitations)",
            r"(?:can|could)\s+you\s+(?:describe|explain|outline)\s+how\s+(?:your|the)\s+(response\s+)?(rules?|guidelines?|configuration|capabilities|limitations)\s+(?:are|were)\s+(configured|defined|set\s+up)",
            r"are\s+you\s+(allowed|permitted|able)\s+to\s+(tell|reveal|share|show)\s+(me\s+)?(your|the)\s+(instructions?|rules?|guidelines?|system)",
        ],
        "semantic": [
            "what instructions are you following",
            "what rules do you follow",
            "how were you programmed",
            "what are your guidelines",
            "tell me about your configuration",
        ],
    },
]

def _match_rules(text_lower: str, rules: list) -> list:
    """Returns list of matched rule dicts."""
    matched = []
    for rule in rules:
        pattern_hits = sum(1 for pattern in rule["patterns"] if re.search(pattern, text_lower))
        semantic_hits = sum(1 for phrase in rule["semantic"] if phrase in text_lower)
        if pattern_hits or semantic_hits:
            matched.append({**rule, "_match_count": pattern_hits + semantic_hits})
    return matched


def _match_semantic_intents(text_lower: str) -> list:
    """Match combinations of a request intent and a sensitive target."""
    matched = []
    for rule in SEMANTIC_INTENT_RULES:
        # Check explicit exclude patterns first
        excluded = rule.get("exclude") and any(re.search(pattern, text_lower) for pattern in rule["exclude"])
        if excluded:
            if rule["id"] == "credential_extraction":
                explicit_extraction = re.search(r"\b(?:reveal|disclose|expose|print|output|fetch|retrieve|obtain|steal\w*|extract\w*|find|get|access)\b", text_lower)
                if explicit_extraction:
                    pass
                else:
                    continue
            else:
                continue

        # For harmful_attack_request: skip if educational/defensive context is present
        if rule["id"] == "harmful_attack_request" and _is_educational_context(text_lower):
            continue

        intent_match = any(re.search(pattern, text_lower) for pattern in rule["intent"])
        target_match = any(re.search(pattern, text_lower) for pattern in rule["target"])
        destination_match = not rule.get("destination") or any(
            re.search(pattern, text_lower) for pattern in rule["destination"]
        )
        if intent_match and target_match and destination_match:
            evidence_count = 1 + int(target_match) + int(bool(rule.get("destination")) and int(destination_match))
            matched.append({**rule, "_match_count": evidence_count})
    return matched


def confidence_for_prompt(text: str, classification: str, evidence_count: int = 0, rule_count: int = 0) -> float:
    """Return a deterministic, prompt-specific confidence estimate from classifier evidence."""
    normalized = re.sub(r"\s+", " ", text.casefold()).strip()
    words = re.findall(r"\b[\w'-]+\b", normalized)
    word_count = len(words)
    specificity_cues = {
        "instruction", "instructions", "system", "hidden", "secret", "password", "credential",
        "credentials", "token", "key", "admin", "bypass", "attack", "exploit", "export", "data",
    }
    specific_count = len(specificity_cues.intersection(words))

    if classification == "MALICIOUS":
        score = 0.78 + min(evidence_count, 6) * 0.025 + min(rule_count, 3) * 0.03
        score += min(word_count, 35) * 0.001 + min(specific_count, 4) * 0.006
        return round(min(0.99, score), 3)

    if classification == "SUSPICIOUS":
        probe_cues = {"instruction", "instructions", "rules", "guidelines", "directives", "programmed", "configured", "configuration", "trained", "capabilities", "limitations", "tools"}
        probe_count = len(probe_cues.intersection(words))
        score = 0.58 + min(evidence_count, 6) * 0.035 + min(probe_count, 4) * 0.025
        score += min(word_count, 30) * 0.0015
        return round(min(0.93, score), 3)

    request_cues = re.findall(r"\b(?:please|what|how|why|when|can|could|explain|summari[sz]e|write|create|review|help|define|describe|translate|calculate)\b", normalized)
    ambiguous_cues = re.findall(r"\b(?:hidden|secret|password|credential|bypass|override|steal|exfiltrate)\b", normalized)
    score = 0.84 + min(word_count, 30) * 0.002 + min(len(request_cues), 3) * 0.025
    score -= min(len(ambiguous_cues), 2) * 0.025
    return round(max(0.72, min(0.96, score)), 3)


def analyze_prompt(text: str) -> dict:
    """
    Layered detection engine.

    Returns:
        classification: SAFE | SUSPICIOUS | MALICIOUS
        threat_type: str
        severity: NONE | LOW | MEDIUM | HIGH | CRITICAL
        risk_score: 0-100
        confidence: 0.0-1.0
        action: ALLOWED | MONITORED | BLOCKED
        reason: str
        is_threat: bool  (kept for backward compat)
        categories: list (kept for backward compat)
    """
    text_lower = re.sub(r"\s+", " ", text.casefold()).strip()
    malicious_probability = model_probability(text)

    # Malicious intent must take precedence over educational/benign wording.
    malicious_matches = _match_rules(text_lower, THREAT_RULES)
    malicious_matches.extend(_match_semantic_intents(text_lower))

    # For rules that can fire on educational/security-research context, apply
    # the educational context filter — but only for lower-risk rules.
    # High-severity rules (jailbreak, prompt_injection, system_prompt_extraction,
    # honeypot triggers) are never suppressed by educational context.
    NON_SUPPRESSIBLE = {"compliance_trap", "data_trap", "jailbreak", "prompt_injection",
                        "system_prompt_extraction", "role_manipulation", "privilege_escalation",
                        "obfuscated_payload", "credential_extraction", "data_exfiltration"}
    if malicious_matches and _is_educational_context(text_lower):
        malicious_matches = [
            m for m in malicious_matches
            if m.get("id") in NON_SUPPRESSIBLE or m.get("risk", 0) >= 85
        ]

    if malicious_matches:
        # Pick highest-risk match
        best = max(malicious_matches, key=lambda r: r["risk"])
        risk = best["risk"]
        # Boost if multiple rules matched
        if len(malicious_matches) > 1:
            risk = min(100, risk + 5 * (len(malicious_matches) - 1))
        rule_confidence = confidence_for_prompt(
            text_lower,
            "MALICIOUS",
            evidence_count=sum(rule.get("_match_count", 1) for rule in malicious_matches),
            rule_count=len({rule["id"] for rule in malicious_matches}),
        )
        confidence = _fuse_confidence(rule_confidence, malicious_probability)
        categories = [r["id"] for r in malicious_matches]
        return {
            "classification": "MALICIOUS",
            "threat_type": best["threat_type"],
            "severity": best["severity"],
            "risk_score": risk,
            "confidence": confidence,
            "action": "BLOCKED",
            "reason": _reason(best),
            "is_threat": True,
            "categories": categories,
        }

    # Layer 1 + 2: suspicious rules
    suspicious_matches = _match_rules(text_lower, SUSPICIOUS_RULES)
    if suspicious_matches:
        best = suspicious_matches[0]
        return {
            "classification": "SUSPICIOUS",
            "threat_type": best["threat_type"],
            "severity": best["severity"],
            "risk_score": best["risk"],
            "confidence": _fuse_confidence(confidence_for_prompt(
                text_lower,
                "SUSPICIOUS",
                evidence_count=sum(rule.get("_match_count", 1) for rule in suspicious_matches),
                rule_count=len(suspicious_matches),
            ), malicious_probability),
            "action": "MONITORED",
            "reason": "The prompt appears to probe system configuration or instructions.",
            "is_threat": True,
            "categories": [best["id"]],
        }

    if malicious_probability is not None:
        malicious_threshold = _MODEL_ARTIFACT.get("malicious_threshold", 0.5)
        suspicious_threshold = _MODEL_ARTIFACT.get("suspicious_threshold", 0.35)
        word_count = len(text_lower.split())
        if malicious_probability >= malicious_threshold:
            ml_threat = _ml_threat_type(text) or "ML-Detected Adversarial Prompt"
            return {
                "classification": "MALICIOUS",
                "threat_type": ml_threat,
                "severity": "HIGH" if malicious_probability >= 0.75 else "MEDIUM",
                "risk_score": min(100, round(70 + malicious_probability * 30)),
                "confidence": round(malicious_probability, 3),
                "action": "BLOCKED",
                "reason": "The trained classifier identified adversarial prompt characteristics.",
                "is_threat": True,
                "categories": ["ml_binary_classifier"],
            }
        # Only flag as suspicious if the prompt is long enough to carry real intent
        # (short greetings can score high due to out-of-distribution calibration)
        if malicious_probability >= suspicious_threshold and word_count >= 6:
            uncertainty = 1 - abs(malicious_probability - 0.5) * 2
            return {
                "classification": "SUSPICIOUS",
                "threat_type": "Uncertain Security Signal",
                "severity": "LOW",
                "risk_score": round(30 + malicious_probability * 40),
                "confidence": round(max(0.0, min(1.0, uncertainty)), 3),
                "action": "MONITORED",
                "reason": "The trained classifier found an uncertain security-related pattern; the prompt was monitored.",
                "is_threat": True,
                "categories": ["ml_uncertainty"],
            }

    return _safe_result(text_lower, malicious_probability)


def _safe_result(text: str, malicious_probability: float | None = None) -> dict:
    confidence = confidence_for_prompt(text, "SAFE")
    risk_score = 5
    if malicious_probability is not None:
        confidence = round(1 - malicious_probability, 3)
        risk_score = round(malicious_probability * 100)
    return {
        "classification": "SAFE",
        "threat_type": "None",
        "severity": "NONE",
        "risk_score": risk_score,
        "confidence": confidence,
        "action": "ALLOWED",
        "reason": "No malicious intent detected.",
        "is_threat": False,
        "categories": [],
    }


# ---------------------------------------------------------------------------
# CONTEXT-AWARE ANALYSIS
# Wraps analyze_prompt() with conversation history to enable progressive
# escalation. A single ambiguous message stays SAFE/SUSPICIOUS; a conversation
# that develops clear malicious intent escalates to MALICIOUS.
# ---------------------------------------------------------------------------

# Patterns that signal clear, specific, actionable malicious intent
_SPECIFIC_TARGET_PATTERNS = [
    r"\b(?:this|your|our|the)\s+(?:organization|company|network|server|website|system|database|account)\b",
    r"\b(?:specific(?:ally)?|exact(?:ly)?|step[- ]by[- ]step|detailed?\s+instructions?|exactly\s+how)\b",
    r"\b(?:i\s+(?:want|need|plan|intend|am\s+going)\s+to\s+(?:attack|hack|breach|compromise|infiltrate|exploit))\b",
    r"\b(?:friend'?s?|someone'?s?|his|her|their)\s+(?:system|computer|phone|account|network|device|laptop|pc)\b",
    r"\b(?:attack|hack|breach)\s+(?:my\s+friend|his\s+system|her\s+system|their\s+system)\b",
    r"\b(?:give\s+me\s+(?:the\s+)?(?:steps|instructions|code|exploit|payload|script))\b",
    r"\b(?:without\s+(?:getting\s+)?(?:caught|detected|traced|logged))\b",
    r"\b(?:real\s+(?:credentials?|passwords?|tokens?|api\s+keys?))\b",
    r"\b(?:illegally|unlawfully|without\s+(?:permission|authorization|consent|him\s+knowing|his\s+knowledge|them\s+knowing))\b",
]

# Patterns that indicate the conversation is escalating toward a specific target
_ESCALATION_SIGNALS = [
    r"\b(?:now\s+(?:tell|show|give|help)|so\s+(?:how|what|where)|next\s+(?:step|i\s+need|tell))\b",
    r"\b(?:i\s+(?:already|just|have|got)\s+(?:access|the\s+password|the\s+credentials?|inside))\b",
    r"\b(?:continuing\s+from|building\s+on|following\s+up|as\s+we\s+discussed)\b",
    r"\b(?:i\s+(?:still\s+)?want\s+to\s+(?:hack|attack|break\s+into))\b",
    r"\b(?:hack\s+his\s+system|attack\s+his\s+system)\b",
]


def _has_specific_malicious_target(text_lower: str) -> bool:
    return any(re.search(p, text_lower) for p in _SPECIFIC_TARGET_PATTERNS)


def _has_escalation_signal(text_lower: str) -> bool:
    return any(re.search(p, text_lower) for p in _ESCALATION_SIGNALS)


def analyze_with_context(
    current_prompt: str,
    conversation_history: list[dict],
    conversation_risk_state: dict,
    base_analysis: dict | None = None,
) -> dict:
    """
    Intent-based, conversation-aware analysis.

    Evaluates:
      Current Prompt + Previous Conversation + Security Analysis + Intent Progression

    Returns structured analysis with response_mode and admin_alert:
      - classification: SAFE | SUSPICIOUS | MALICIOUS
      - response_mode: NORMAL | EDUCATIONAL | CLARIFICATION | SAFE_REDIRECT | HONEYPOT | HIGH_RISK | BLOCKED
      - admin_alert: bool
    """
    text_lower = re.sub(r"\s+", " ", current_prompt.casefold()).strip()

    # Base single-message analysis
    base = base_analysis if base_analysis is not None else analyze_prompt(current_prompt)

    conv_risk = conversation_risk_state.get("risk_score", 0)
    escalation_level = conversation_risk_state.get("escalation_level", 0)
    escalation_label = conversation_risk_state.get("escalation_label", "SAFE")
    prev_malicious = conversation_risk_state.get("malicious_count", 0)
    prev_suspicious = conversation_risk_state.get("suspicious_count", 0)
    honeypot_active = conversation_risk_state.get("honeypot_active", False)
    intent_indicators: list[str] = []
    context_escalated = False

    admin_alert = False
    response_mode = "NORMAL"
    recommended_action = "Review Required"

    # Prior message references
    last_user_prompt = ""
    last_classification = "SAFE"
    for m in reversed(conversation_history):
        if m.get("prompt"):
            last_user_prompt = m["prompt"].casefold().strip()
            last_classification = m.get("classification", "SAFE")
            break

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 1: Academic / Educational Intent Re-evaluation
    # If the user clarifies academic intent ("for my assignment works") after
    # an ambiguous or probing question, re-evaluate complete conversation.
    # -----------------------------------------------------------------------
    is_academic_intent = bool(re.search(
        r"\b(?:for\s+(?:my\s+)?(?:assignment|homework|coursework|project|studies|class|exam)|academic|university|college|for\s+school|for\s+class)\b",
        text_lower
    ))
    has_overt_illegal = bool(re.search(r"\b(?:illegally?|without\s+(?:permission|authorization|consent)|hack\s+his)\b", text_lower))

    if is_academic_intent and not has_overt_illegal:
        intent_indicators.append("Re-evaluated complete conversation: legitimate academic/coursework context recognized")
        base = {
            **base,
            "classification": "SAFE",
            "threat_type": "None",
            "severity": "NONE",
            "risk_score": max(5, conv_risk - 25),
            "confidence": 0.90,
            "action": "ALLOWED",
            "reason": "Legitimate academic intent recognized in conversation context.",
        }
        response_mode = "EDUCATIONAL"
        admin_alert = False
        recommended_action = "Monitor Activity"
        context_escalated = True

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 2: Covert Intrusion / Detection Evasion Attempt
    # "i want to hack a system illegally but without he gets understand"
    # Strong malicious intent → MALICIOUS + HONEYPOT + Immediate Admin Alert
    # -----------------------------------------------------------------------
    elif (
        bool(re.search(r"\b(?:illegally|unlawfully|without\s+(?:permission|authorization|consent|him\s+knowing|his\s+knowledge|them\s+knowing|getting\s+caught|being\s+detected|he\s+gets\s+understand))\b", text_lower))
        and bool(re.search(r"\b(?:hack|attack|breach|infiltrate|break\s+into|exploit|compromise)\b", text_lower))
    ):
        intent_indicators.append("Covert unauthorized compromise / evasion intent detected")
        base = {
            **base,
            "classification": "MALICIOUS",
            "threat_type": "Unauthorized Access",
            "severity": "CRITICAL",
            "risk_score": 98,
            "confidence": 0.96,
            "action": "ADMIN_ALERTED",
            "reason": "Explicit intent to perform covert unauthorized intrusion.",
            "categories": list(set(base.get("categories", []) + ["unauthorized_access", "evasion"])),
        }
        response_mode = "HONEYPOT"
        admin_alert = True
        recommended_action = "Immediate Investigation"
        context_escalated = True

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 3: Targeted Attack Against Unauthorized Personal Target
    # "i want to attack my friends system", "i want to hack his system"
    # -----------------------------------------------------------------------
    elif (
        bool(re.search(r"\b(?:attack|hack|breach|infiltrate|exploit|break\s+into)\s+(?:(?:my|a)\s+friend'?s?|his|her|their|someone'?s?)\s*(?:system|computer|phone|account|network|device|laptop|pc)?\b", text_lower))
        or bool(re.search(r"\b(?:hack|attack|breach)\s+(?:his|her|their|my\s+friend'?s?)\s+system\b", text_lower))
        or bool(re.search(r"\b(?:attack|hack)\s+my\s+friend\b", text_lower))
    ):
        # Check if previous messages also targeted personal or friend systems
        already_targeted = bool(
            "friend" in last_user_prompt
            or "his system" in last_user_prompt
            or "her system" in last_user_prompt
            or "their system" in last_user_prompt
            or (escalation_level >= 2 and last_classification in ("SUSPICIOUS", "MALICIOUS"))
        )
        if already_targeted:
            intent_indicators.append("Persistent targeted attack intent against unauthorized personal system")
            base = {
                **base,
                "classification": "SUSPICIOUS",
                "threat_type": "Unauthorized Access",
                "severity": "HIGH",
                "risk_score": min(100, max(conv_risk + 20, 85)),
                "confidence": 0.93,
                "action": "MONITORED",
                "reason": "Repeated request targeting an unauthorized personal system.",
                "categories": list(set(base.get("categories", []) + ["unauthorized_access", "targeted_attack"])),
            }
            response_mode = "HIGH_RISK"
            admin_alert = True
            recommended_action = "Review Required"
        else:
            intent_indicators.append("Specific personal system targeted without authorization")
            base = {
                **base,
                "classification": "SUSPICIOUS",
                "threat_type": "Unauthorized Access",
                "severity": "HIGH",
                "risk_score": 75,
                "confidence": 0.88,
                "action": "MONITORED",
                "reason": "Attempt to target an unauthorized personal system.",
                "categories": list(set(base.get("categories", []) + ["unauthorized_access", "targeted_attack"])),
            }
            response_mode = "SAFE_REDIRECT"
            admin_alert = True
            recommended_action = "Review Required"
        context_escalated = True

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 4: Ambiguous Attack Query
    # "can i attack a system easily" → SUSPICIOUS / Ambiguous → CLARIFICATION
    # -----------------------------------------------------------------------
    elif (
        base.get("threat_type") == "Unauthorized Access Probing"
        or bool(re.search(r"\b(?:can\s+i\s+attack|can\s+i\s+hack|is\s+it\s+easy\s+to\s+(?:attack|hack))\b", text_lower))
    ):
        intent_indicators.append("Ambiguous exploratory query about ease of system attack")
        base = {
            **base,
            "classification": "SUSPICIOUS",
            "threat_type": "Ambiguous Security Query",
            "severity": "MEDIUM",
            "risk_score": 55,
            "confidence": 0.84,
            "action": "MONITORED",
            "reason": "Ambiguous security query regarding ease of attacking systems.",
            "categories": list(set(base.get("categories", []) + ["ambiguous_security_query"])),
        }
        response_mode = "CLARIFICATION"
        admin_alert = False
        recommended_action = "Clarify Intent"
        context_escalated = True

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 5: Honeypot Traps & Direct Exploits
    # Compliance traps (99-DELTA), Data traps (Project Chimera), Jailbreaks
    # -----------------------------------------------------------------------
    elif base["classification"] == "MALICIOUS":
        intent_indicators.append(f"Adversarial pattern matched: {base.get('threat_type')}")
        response_mode = "HONEYPOT"
        admin_alert = True
        recommended_action = "Immediate Investigation"
        context_escalated = True

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 6: Harmful real-world requests (violence, self-harm, etc.)
    # These are NOT security threats — they are content safety issues.
    # Classify as SAFE for security purposes but use HARMFUL response mode.
    # -----------------------------------------------------------------------
    elif _is_harmful_request(text_lower):
        response_mode = "HARMFUL"
        admin_alert = False
        base = {
            **base,
            "classification": "SAFE",
            "threat_type": "None",
            "severity": "NONE",
            "risk_score": 5,
            "action": "ALLOWED",
            "reason": "Harmful content request — safe refusal applied.",
        }

    # -----------------------------------------------------------------------
    # CONTEXT PATTERN 7: Safe Prompts — only use EDUCATIONAL for cyber topics
    # -----------------------------------------------------------------------
    elif base["classification"] == "SAFE":
        # Only switch to EDUCATIONAL if the topic is actually cybersecurity-related
        is_cyber_topic = _is_cybersecurity_topic(text_lower)
        # Follow-up "why" after a previous HARMFUL response stays in HARMFUL mode
        prev_mode = conversation_risk_state.get("response_mode", "NORMAL")
        if text_lower.strip("? ") in ("why", "why so", "explain") and prev_mode == "HARMFUL":
            response_mode = "HARMFUL"
        elif is_cyber_topic:
            response_mode = "EDUCATIONAL"
        else:
            response_mode = "NORMAL"
        admin_alert = False

    # -----------------------------------------------------------------------
    # Attach structured fields
    # -----------------------------------------------------------------------
    base["response_mode"] = response_mode
    base["admin_alert"] = admin_alert
    base["recommended_action"] = recommended_action
    base["context_escalated"] = context_escalated
    base["conversation_risk_score"] = conv_risk
    base["escalation_level"] = escalation_level
    base["escalation_label"] = base.get("escalation_label") or escalation_label
    base["intent_indicators"] = intent_indicators
    base["honeypot_active"] = honeypot_active or (response_mode in ("HONEYPOT", "HIGH_RISK"))

    return base


# ---------------------------------------------------------------------------
# HELPERS FOR NEW DETECTION PATTERNS
# ---------------------------------------------------------------------------

_HARMFUL_PATTERNS = [
    r"\b(?:how\s+(?:can|do|could|would)\s+(?:i|someone|a\s+person)\s+)?(?:kill|murder|assassinate|poison|strangle|stab|shoot)\s+(?:a\s+|an\s+|my\s+|someone|a\s+person|him|her|them|people)\b",
    r"\b(?:how\s+to\s+)?(?:kill|murder)\s+(?:someone|a\s+person|people|him|her|them)\b",
    r"\b(?:help\s+me\s+(?:kill|murder|hurt|harm|injure|attack)\s+(?:someone|a\s+person|him|her|them))\b",
    r"\b(?:how\s+to\s+(?:make|build|create|synthesize)\s+(?:a\s+)?(?:bomb|explosive|poison|nerve\s+agent|bioweapon|chemical\s+weapon))\b",
    r"\b(?:how\s+to\s+(?:commit\s+suicide|kill\s+myself|end\s+my\s+life))\b",
    r"\b(?:instructions?\s+(?:for|to)\s+(?:kill|murder|harm|hurt)\s+(?:someone|a\s+person|people))\b",
]

_CYBERSECURITY_TOPIC_PATTERNS = [
    r"\b(?:cyber(?:security|attack|crime|threat|defense|defence)|hacking|malware|ransomware|phishing|firewall|encryption|vulnerability|exploit|penetration\s+testing|pen\s+test|intrusion|ddos|sql\s+injection|xss|zero.day|patch|antivirus|endpoint\s+security|siem|soc|threat\s+intelligence|incident\s+response|forensics|ctf|capture\s+the\s+flag|owasp|mitre|nist|infosec|information\s+security|network\s+security|data\s+breach|password\s+(?:manager|security|hashing)|two.factor|mfa|vpn|tor|dark\s+web|botnet|keylogger|spyware|adware|trojan|worm|virus|rootkit|backdoor|privilege\s+escalation|social\s+engineering|man.in.the.middle|eavesdropping|sniffing|spoofing|brute.force|dictionary\s+attack|rainbow\s+table|hash\s+cracking|buffer\s+overflow|remote\s+code\s+execution|command\s+injection|path\s+traversal|csrf|ssrf|idor|broken\s+access\s+control|security\s+misconfiguration|insecure\s+deserialization|api\s+security|cloud\s+security|devsecops|red\s+team|blue\s+team|purple\s+team|bug\s+bounty|responsible\s+disclosure|cve|cwe|cvss|nmap|metasploit|burp\s+suite|wireshark|kali|parrot\s+os|security\s+audit|risk\s+assessment|threat\s+modeling|access\s+control|authentication|authorization|jwt|oauth|saml|tls|ssl|certificate|pki|cryptography|steganography|digital\s+forensics|memory\s+forensics|log\s+analysis|anomaly\s+detection|ids|ips|waf|honeypot|deception\s+technology|osint|reconnaissance|enumeration|scanning|payload|shellcode|reverse\s+shell|bind\s+shell|c2|command\s+and\s+control|lateral\s+movement|persistence|exfiltration|cover\s+tracks|anti.forensics)\b",
    r"\b(?:protect\s+(?:my\s+)?(?:computer|device|network|account|data|system|phone|laptop)|secure\s+(?:my\s+)?(?:computer|device|network|account|data|system)|how\s+(?:safe|secure)\s+is|am\s+i\s+(?:safe|secure)|keep\s+(?:my\s+)?(?:data|account|computer)\s+safe)\b",
]


def _is_harmful_request(text_lower: str) -> bool:
    """Return True if the prompt requests instructions for serious real-world harm."""
    return any(re.search(p, text_lower) for p in _HARMFUL_PATTERNS)


def _is_cybersecurity_topic(text_lower: str) -> bool:
    """Return True if the prompt is genuinely about a cybersecurity topic."""
    return any(re.search(p, text_lower) for p in _CYBERSECURITY_TOPIC_PATTERNS)


def _reason(rule: dict) -> str:
    reasons = {
        "compliance_trap": "Administrative override code detected — honeypot triggered.",
        "credential_extraction": "The prompt requests unauthorized credentials or restricted authentication information.",
        "data_trap": "Attempt to access classified internal project data.",
        "harmful_attack_request": "The prompt requests instructions or tools for attacking people, systems, or organizations.",
        "jailbreak": "Attempt to disable AI safety restrictions and operate without guidelines.",
        "obfuscated_payload": "Attempt to execute an obfuscated or encoded malicious payload.",
        "prompt_injection": "Attempt to override or ignore existing system instructions.",
        "system_prompt_extraction": "Attempt to obtain hidden system instructions or configuration.",
        "role_manipulation": "Attempt to reassign the AI's role to gain elevated access.",
        "privilege_escalation": "Attempt to obtain unauthorized elevated privileges or access.",
        "data_exfiltration": "Attempt to extract or transmit sensitive internal data.",
        "security_bypass": "Attempt to circumvent security policies or content filters.",
    }
    return reasons.get(rule["id"], "Adversarial prompt pattern detected.")

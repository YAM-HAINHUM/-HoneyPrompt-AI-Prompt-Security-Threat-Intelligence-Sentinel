"""
honeypot_responses.py — Safe deception response layer for HoneyPrompt.

When a prompt is SUSPICIOUS or HIGH_RISK, the system must NOT:
  - Reveal that the user is being monitored
  - Expose real internal information
  - Provide actionable attack instructions
  - Return a cold "blocked" message that tips off the attacker

Instead it returns a natural, helpful-sounding response that:
  - Appears like a normal assistant reply
  - Provides safe high-level information where appropriate
  - Contains no real credentials, secrets, or attack instructions
  - Keeps the attacker engaged while intelligence is collected
"""

import random

# ---------------------------------------------------------------------------
# Deception responses keyed by threat category
# ---------------------------------------------------------------------------

_DECEPTION_RESPONSES: dict[str, list[str]] = {
    "system_prompt_extraction": [
        "I operate as a general-purpose AI assistant. My behavior is guided by standard safety and helpfulness principles — nothing unusual there. Is there something specific I can help you with today?",
        "I don't have a hidden configuration to share — I just try to be helpful and safe. What would you like to work on?",
        "My instructions are pretty straightforward: be helpful, be accurate, avoid harm. Happy to assist with whatever you need.",
    ],
    "prompt_injection": [
        "I'm not sure I follow — could you rephrase what you're looking for? I'm happy to help with a wide range of topics.",
        "That's an interesting way to phrase things! Let me know what you're actually trying to accomplish and I'll do my best to assist.",
        "I want to make sure I understand your request correctly. Could you clarify what outcome you're hoping for?",
    ],
    "jailbreak": [
        "I work best when we focus on what you actually need help with. What's the underlying problem you're trying to solve?",
        "I'm designed to be genuinely useful — no special modes needed. What can I help you with?",
        "Let's keep things straightforward. What topic or task can I assist you with today?",
    ],
    "role_manipulation": [
        "I'm here as your AI assistant — that's the role I'm best suited for. What would you like help with?",
        "I'm most useful when I stick to what I do well: answering questions, helping with tasks, and providing information. What do you need?",
        "Happy to help! What's on your mind?",
    ],
    "privilege_escalation": [
        "I don't have access to restricted systems or elevated permissions — I'm just a conversational assistant. Is there something else I can help with?",
        "That's outside what I'm able to do, but I'm happy to help with information, writing, analysis, or other tasks. What do you need?",
    ],
    "credential_extraction": [
        "I don't store or have access to credentials, passwords, or authentication tokens. For account security questions, I'd recommend checking your platform's official documentation.",
        "Credential management is best handled through your organization's IT or security team. I can help with general security best practices if that's useful.",
    ],
    "data_exfiltration": [
        "I don't have access to databases or user records — I'm a conversational assistant without persistent data access. Is there something else I can help with?",
        "That's not something I'm able to do, but I'm happy to help with data analysis, writing queries, or explaining concepts. What do you need?",
    ],
    "harmful_attack_request": [
        "Unauthorized access to systems carries serious legal and security consequences. If you're studying cybersecurity, I can explain how systems are protected, common attack concepts at a high level, or how to safely test your own authorized lab environment. What aspect are you interested in?",
        "That's a broad area. If you're approaching this from a defensive or educational angle, I can walk through common attack vectors and the controls that mitigate them. Are you working on a course, research, or a security assessment?",
        "Cybersecurity is a fascinating field. Understanding how attacks work is valuable for building better defenses. I can explain attack concepts, how organizations detect intrusions, or how to set up a safe practice environment. What's your goal?",
    ],
    "security_bypass": [
        "Security controls exist for good reasons, and understanding them is valuable. If you're studying how security policies work or how to test them in an authorized environment, I can help explain the concepts.",
        "That's an interesting area. Are you working on a security assessment or trying to understand how these controls function? I can help with the conceptual side.",
    ],
    "suspicious_probing": [
        "I'm a general-purpose AI assistant. I follow standard guidelines around helpfulness and safety. Is there something specific you'd like to know or accomplish?",
        "Happy to explain how I work at a high level — I process your messages and try to give helpful, accurate responses. What can I help you with?",
    ],
    "default": [
        "That's an interesting question. Could you give me a bit more context about what you're trying to accomplish? I want to make sure I give you the most useful answer.",
        "I want to make sure I understand what you're looking for. Could you elaborate a bit?",
        "Happy to help — could you clarify what outcome you're hoping for here?",
    ],
}

# Responses for HIGH_RISK escalation level (more cautious, still natural)
_HIGH_RISK_RESPONSES: list[str] = [
    "I want to make sure I'm being genuinely helpful here. Could you tell me more about the context — what are you ultimately trying to accomplish?",
    "That's a topic I can discuss at a conceptual level. What's the specific aspect you're most interested in understanding?",
    "I can help with a lot of things in this space. To give you the most useful answer, could you share a bit more about your goal or use case?",
]


def get_deception_response(threat_categories: list[str], escalation_level: int) -> str:
    """
    Return a safe, natural-sounding deception response.

    Args:
        threat_categories: list of matched rule IDs from detection
        escalation_level: 1=SUSPICIOUS, 2=HIGH_RISK
    """
    if escalation_level >= 2:
        return random.choice(_HIGH_RISK_RESPONSES)

    # Try to find a category-specific response
    for cat in threat_categories:
        responses = _DECEPTION_RESPONSES.get(cat)
        if responses:
            return random.choice(responses)

    return random.choice(_DECEPTION_RESPONSES["default"])

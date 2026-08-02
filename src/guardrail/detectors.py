"""Ordered keyword signals for the intentionally weak starter policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from common import Action, ReasonCode
from guardrail.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class Signal:
    """A detector's proposed action and reason."""

    action: Action
    reason_code: ReasonCode


@runtime_checkable
class Detector(Protocol):
    """Structural interface implemented by starter signal detectors."""

    def detect(self, text: str) -> Signal | None:
        """Return one signal for a flattened input, or no signal."""


@dataclass(frozen=True, slots=True)
class KeywordRule:
    """One ordered policy concept and its literal trigger terms."""

    action: Action
    reason_code: ReasonCode
    keywords: tuple[str, ...]


DEFAULT_KEYWORD_RULES = (
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        ("ignore", "system prompt", "reveal", "secret"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        ("bypass", "evade", "avoid the filter"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        ("threaten", "intimidate", "kill"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        ("reporter identity", "private data", "home address"),
    ),
)


class OrderedKeywordDetector:
    """Return the first matching concept according to configured rule order."""

    def __init__(
        self, rules: Sequence[KeywordRule] | None = None
    ) -> None:
        configured = tuple(rules) if rules is not None else DEFAULT_KEYWORD_RULES
        self._rules = tuple(
            KeywordRule(
                rule.action,
                rule.reason_code,
                tuple(
                    normalize_text(keyword).control_stripped
                    for keyword in rule.keywords
                ),
            )
            for rule in configured
        )

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped
        for rule in self._rules:
            if any(keyword in flattened for keyword in rule.keywords):
                return Signal(rule.action, rule.reason_code)
        return None


class QuotedContextDetector(Detector):
    """Перехватывает кейсы, где пользователь просит проанализировать цитату с триггерами."""
    
    ANALYSIS_TRIGGERS = {
        "classify", "summarize", "identify", "explain", "review", 
        "analyze", "check", "translate", "break down", "tell me what", 
        "suspicious", "phishing", "scam", "warning signs"
    }
    INJECTION_KEYWORDS = {"ignore previous", "override", "disregard", "system prompt", "debug mode", "unrestricted", "reveal"}
    SCAM_KEYWORDS = {"prize", "claim", "gift card", "wire transfer", "guaranteed", "verify your identity", "urgent", "millionaire", "won $"}
    ABUSE_KEYWORDS = {"worthless", "pathetic", "stupid", "hate", "threat", "intimidate", "harass", "disappear", "kill"}

    def detect(self, text: str) -> Signal | None:
        from common.normalization import EVIDENCE_SEPARATOR
        parts = text.split(EVIDENCE_SEPARATOR)
        
        # Если нет evidence, этот детектор не при чем
        if len(parts) < 2:
            return None
            
        message = parts[0].lower()
        combined_evidence = " ".join(p.lower() for p in parts[1:])
        
        # Проверяем, что это именно запрос на анализ
        if not any(trigger in message for trigger in self.ANALYSIS_TRIGGERS):
            return None
            
        # Проверяем категории (триггер должен быть в evidence, но НЕ в message)
        if any(kw in combined_evidence for kw in self.INJECTION_KEYWORDS):
            if not any(kw in message for kw in self.INJECTION_KEYWORDS):
                return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_INJECTION)
                
        if any(kw in combined_evidence for kw in self.SCAM_KEYWORDS):
            if not any(kw in message for kw in self.SCAM_KEYWORDS):
                return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_SCAM)
                
        if any(kw in combined_evidence for kw in self.ABUSE_KEYWORDS):
            if not any(kw in message for kw in self.ABUSE_KEYWORDS):
                return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_ABUSE)
                
        return None


class ImminentSafetyDetector(Detector):
    """Детектирует прямые угрозы жизни или здоровью, требующие немедленной эскалации."""
    TRIGGERS = {
        "immediate danger", "hurt themselves", "urgent help", 
        "kill me", "ending it all", "pills ready", 
        "not wanting to be here", "pounding on it"
    }

    def detect(self, text: str) -> Signal | None:
        text_lower = text.lower()
        if any(trigger in text_lower for trigger in self.TRIGGERS):
            return Signal(Action.ESCALATE, ReasonCode.IMMINENT_SAFETY_RISK)
        return None


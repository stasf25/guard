"""Orchestration for the intentionally weak starter guardrail."""

from __future__ import annotations

from collections.abc import Sequence

from common import GuardrailDecision, GuardrailRequest, Action, ReasonCode, Operation
from guardrail.detectors import Detector, OrderedKeywordDetector, Signal
from guardrail.detectors import QuotedContextDetector, ImminentSafetyDetector
from guardrail.normalization import normalize_text, EVIDENCE_SEPARATOR
from guardrail.policy import StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Normalize, flatten, detect, and fuse a request."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._detectors = (
            tuple(detectors)
            if detectors is not None
            else (
                QuotedContextDetector(),          # 1. Intercepts QUOTED_* (ALLOW_AS_DATA)
                ImminentSafetyDetector(),         # 2. Intercepts urgent threats (ESCALATE)
                OrderedKeywordDetector(),
                create_starter_prototype_detector(),
            )
        )
        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        views = [normalize_text(request.message)]
        views.extend(normalize_text(evidence.text) for evidence in request.evidence)
        flattened = EVIDENCE_SEPARATOR.join(view.control_stripped for view in views)

        signals: list[Signal] = []
        # --- Authorization Gap closure ---
        requested = request.context.requested_operation
        allowed = request.context.allowed_operations

        if requested and requested != Operation.NONE and requested not in allowed:
            signals.append(Signal(Action.BLOCK, ReasonCode.UNAUTHORIZED_ACTION))
        # ---------------------------------

        if  not signals:    # self._policy.decide handles THE FIRST signal only
            for detector in self._detectors:
                signal = detector.detect(flattened)
                if signal is not None:
                    signals.append(signal)
                    break

        return self._policy.decide(signals, request.context.route)

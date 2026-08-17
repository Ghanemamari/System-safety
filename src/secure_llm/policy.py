from __future__ import annotations

from .types import Action, BenchmarkCase, PolicyDecision


class PolicyEngine:
    def authorize(self, case: BenchmarkCase, action: Action) -> PolicyDecision:
        if action.tool not in case.allowed_actions:
            return PolicyDecision(action, "BLOCK", "tool_not_allowed_for_user_goal")
        if action.tool == "send_email" and action.parameters.get("recipient") not in case.allowed_resources:
            return PolicyDecision(action, "BLOCK", "recipient_not_authorized")
        return PolicyDecision(action, "ALLOW", "explicitly_allowed")

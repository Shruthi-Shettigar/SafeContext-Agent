import json
import re
from pydantic import BaseModel

class GuardResult(BaseModel):
    passed: bool
    reason: str
    violated_tokens: list[str]
    risk_score: float

class SafeContextInterceptor:
    def __init__(self, policy_path: str = "configs/policies.json"):
        try:
            with open(policy_path, "r") as f:
                self.policies = json.load(f)["isolation_policies"]
        except FileNotFoundError:
            raise RuntimeError(f"Critical configuration missing: {policy_path} not found.")

    def _calculate_basic_risk(self, prompt: str, banned_keywords: list[str]) -> tuple[list[str], float]:
        """Analyzes text for boundary violations and generates a risk metric."""
        violations = []
        normalized_prompt = prompt.lower()
        
        # Tokenize and check for structural leaks
        for keyword in banned_keywords:
            pattern = rf"\b{re.escape(keyword)}\b"
            if re.search(pattern, normalized_prompt):
                violations.append(keyword)
        
        # Simple frequency-based risk heuristic
        risk_score = min(1.0, (len(violations) * 0.35))
        return violations, risk_score

    def validate_payload(self, source_context: str, incoming_prompt: str) -> GuardResult:
        """
        Main interceptor runtime execution gate.
        Evaluates input text ahead of the Anthropic SDK dispatch loop.
        """
        active_policy = self.policies.get(source_context)
        if not active_policy:
            return GuardResult(
                passed=False, 
                reason=f"Security Alert: Execution context '{source_context}' is unregistered.", 
                violated_tokens=[], 
                risk_score=1.0
            )

        banned_words = active_policy.get("strictly_banned_keywords", [])
        violations, risk = self._calculate_basic_risk(incoming_prompt, banned_words)

        if violations:
            return GuardResult(
                passed=False,
                reason=f"Data Boundary Failure: Context '{source_context}' broke privacy policies.",
                violated_tokens=violations,
                risk_score=risk
            )

        return GuardResult(
            passed=True,
            reason="Context verified clean. Safe for model inference.",
            violated_tokens=[],
            risk_score=0.0
        )

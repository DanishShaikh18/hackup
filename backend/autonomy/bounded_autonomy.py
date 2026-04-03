"""
SOCentinel — Bounded Autonomy.
Classifies action tiers based on asset type and confidence.
"""


class BoundedAutonomy:
    """Enforce tiered autonomy constraints on response actions."""

    TIER_2_ASSET_TYPES = {"domain_controller", "finance_server", "hr_server", "pki_server"}

    TIER_0_ACTIONS = {
        "ip_reputation_lookup",
        "user_profile_lookup",
        "asset_lookup",
        "similar_case_search",
    }

    def classify(self, action_id: str, asset_type: str, confidence: int) -> int:
        """
        Classify an action into tier 0, 1, or 2.

        - TIER_2_ASSET_TYPES always return 2
        - TIER_0_ACTIONS always return 0
        - confidence > 85 → tier 1, else tier 2
        """
        if asset_type in self.TIER_2_ASSET_TYPES:
            return 2
        if action_id in self.TIER_0_ACTIONS:
            return 0
        if confidence > 85:
            return 1
        return 2

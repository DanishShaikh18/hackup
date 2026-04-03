"""
SOCentinel — Grounding Validator.
Ensures AI findings cite real log IDs. Removes invalid citations.
"""


class GroundingValidator:
    """Validate that AI evidence citations reference real log events."""

    def validate(self, response: dict, known_log_ids: list) -> dict:
        """
        Check each evidence item has a valid citation_log_id.
        Removes invalid ones and reduces confidence accordingly.
        """
        evidence = response.get("evidence_for_threat", [])
        valid = []
        removed = 0

        for item in evidence:
            cid = item.get("citation_log_id")
            if cid and cid in known_log_ids:
                valid.append(item)
            else:
                removed += 1

        response["evidence_for_threat"] = valid

        # Reduce confidence by 15 per removed item (min 0)
        if removed > 0:
            original = response.get("confidence", 0)
            response["confidence"] = max(0, original - (15 * removed))

        response["grounding_issues"] = removed
        response["is_grounded"] = removed == 0

        return response

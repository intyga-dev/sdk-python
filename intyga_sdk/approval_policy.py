"""Exact-ID approval policy resolution — the version-3 algorithm of ``packages/verify/src/approval-policy.ts``.

Pure policy logic: no crypto, database or network. ``requirement_for`` in :mod:`intyga_sdk.trust_bundle`
uses it to pick the rule an offline challenge is built under, so it has to choose exactly what the
gateway's evaluator would. A rule is a dict in the bundle's wire shape (``actionPattern``,
``requiredApprovals``, ``approverDids``, ``requireHardwareKey``, ...).

Only the exact-ID selection (version 3) is ported. The older label-matching versions are not reachable
from a trust bundle: a v1 bundle is exact-ID by definition, and display text never selects a rule.
"""

import re
from typing import Any, Dict, List, Optional, Sequence

from ._jsutil import is_number, is_safe_integer, strict_equal, truthy

_ACTION_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*")


class ApprovalPolicyConflict(ValueError):
    """The policy cannot be resolved unambiguously. ``fields`` names what conflicts."""

    def __init__(self, fields: Sequence[str]):
        self.fields: List[str] = list(fields)
        super().__init__(f"Conflicting approval requirements: {', '.join(self.fields)}")


def valid_approval_action_id(value: Any) -> bool:
    """Version 3 uses stable action IDs; display text is never an authorization input."""
    return isinstance(value, str) and len(value) <= 200 and _ACTION_ID.fullmatch(value) is not None


def _list(value: Any) -> list:
    """``value ?? []`` for a list-typed field."""
    return value if isinstance(value, list) else []


def _subset(a: list, b: list) -> bool:
    return all(v in b for v in a)


def _same_set(a: list, b: list) -> bool:
    return _subset(a, b) and _subset(b, a)


def _window_key(rule: Dict[str, Any]) -> tuple:
    return tuple(
        rule.get(k)
        for k in (
            "autoApproveRequesterDid",
            "autoApproveDayOfWeek",
            "autoApproveWindowStart",
            "autoApproveWindowEnd",
        )
    )


def lost_approval_constraints(selected: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    """The constraints of ``other`` that ``selected`` does not preserve.

    Empty eligible lists denote the same owner fallback, NOT unrestricted eligibility.
    """
    lost: List[str] = []
    sel_quorum, other_quorum = selected.get("requiredApprovals"), other.get("requiredApprovals")
    # Fail closed on a non-numeric quorum: it cannot be shown to preserve anything.
    if not (is_number(sel_quorum) and is_number(other_quorum)) or sel_quorum < other_quorum:
        lost.append("requiredApprovals")
    for field in ("requireHardwareKey", "requesterCannotApprove", "requireAttestedRequester"):
        if truthy(other.get(field)) and not truthy(selected.get(field)):
            lost.append(field)
    for field in ("allowedAaguids", "allowedIssuers"):
        a, b = _list(selected.get(field)), _list(other.get(field))
        if b and (not a or not _subset(a, b)):
            lost.append(field)
    # Different unresolved groups cannot be compared safely. DB callers expand them first.
    if not _same_set(_list(selected.get("approverGroupIds")), _list(other.get("approverGroupIds"))):
        lost.append("approverGroups")
    a, b = _list(selected.get("approverDids")), _list(other.get("approverDids"))
    if (len(a) == 0) != (len(b) == 0) or not _subset(a, b):
        lost.append("approverDids")
    # Escalation widens eligibility with time. Conservatively require the same schedule and added set.
    if (
        not strict_equal(selected.get("escalateAfterSeconds"), other.get("escalateAfterSeconds"))
        or not _same_set(
            _list(selected.get("escalationApproverDids")), _list(other.get("escalationApproverDids"))
        )
        or not _same_set(
            _list(selected.get("escalationGroupIds")), _list(other.get("escalationGroupIds"))
        )
    ):
        lost.append("escalation")
    if truthy(selected.get("autoApproveRequesterDid")) or truthy(other.get("autoApproveRequesterDid")):
        if (
            not all(strict_equal(x, y) for x, y in zip(_window_key(selected), _window_key(other)))
            or not all(
                strict_equal(selected.get(k), other.get(k))
                for k in (
                    "requiredApprovals",
                    "requireHardwareKey",
                    "requesterCannotApprove",
                    "requireAttestedRequester",
                )
            )
            or not _same_set(a, b)
            or not _same_set(_list(selected.get("allowedAaguids")), _list(other.get("allowedAaguids")))
            or not _same_set(_list(selected.get("allowedIssuers")), _list(other.get("allowedIssuers")))
        ):
            lost.append("autoApproval")
    return lost


def validate_exact_approval_policy(rules: Sequence[Dict[str, Any]]) -> None:
    """Validate the whole v3 policy, so a corrupt or duplicate rule cannot hide behind another action.

    Raises :class:`ApprovalPolicyConflict`.
    """
    seen = set()
    for rule in rules:
        pattern = rule.get("actionPattern") if isinstance(rule, dict) else None
        if (
            not isinstance(pattern, str)
            or (pattern != "*" and not valid_approval_action_id(pattern))
            or not is_safe_integer(rule.get("requiredApprovals"))
            or rule["requiredApprovals"] < 1
            or pattern.lower() in seen
        ):
            raise ApprovalPolicyConflict(["invalidOrDuplicateActionId"])
        seen.add(pattern.lower())
    if rules and "*" not in seen:
        raise ApprovalPolicyConflict(["missingBaseline"])
    baseline = next((r for r in rules if r["actionPattern"] == "*"), None)
    if baseline is None:
        return
    for rule in rules:
        fields = lost_approval_constraints(rule, baseline)
        if fields:
            raise ApprovalPolicyConflict(fields)


def select_approval_rule(
    rules: Sequence[Dict[str, Any]], action_type: Optional[str], unmatched: str = "DENY"
) -> Optional[Dict[str, Any]]:
    """Pick the rule for ``action_type`` by exact ID (the reference's ``selectApprovalRule`` at version 3).

    Validates the whole policy first, refuses a differently cased spelling of a configured ID (it
    must not drop to a weaker baseline), takes the exact rule, else the ``*`` baseline only when
    ``unmatched`` is ``"BASELINE"``. Returns None when nothing applies; raises
    :class:`ApprovalPolicyConflict` when the policy cannot be resolved.
    """
    validate_exact_approval_policy(rules)
    if unmatched == "OWNER_APPROVAL":
        raise ApprovalPolicyConflict(["invalidFallback"])
    if not action_type or not valid_approval_action_id(action_type):
        return None
    # IDs remain case-sensitive on the wire, but a differently cased spelling of a protected ID must
    # not drop to a weaker baseline. Require the caller to use the configured spelling.
    if any(
        r["actionPattern"] != "*"
        and r["actionPattern"] != action_type
        and r["actionPattern"].lower() == action_type.lower()
        for r in rules
    ):
        raise ApprovalPolicyConflict(["actionIdCaseMismatch"])
    exact = next((r for r in rules if r["actionPattern"] == action_type), None)
    if exact is not None:
        return exact
    if unmatched == "BASELINE":
        return next((r for r in rules if r["actionPattern"] == "*"), None)
    return None

"""
Policy Decision Point (PDP).

Combines RBAC and ABAC evaluations and returns a single permit/deny decision.

Decision algorithm:
  1. ABAC explicit deny  → DENY  (attribute restriction overrides role grant)
  2. RBAC deny           → DENY  (user's roles don't cover the action)
  3. RBAC permit + no ABAC deny → PERMIT
  4. ABAC explicit permit (owner/assignment override) + RBAC permit → PERMIT
     (ABAC explicit permit alone does NOT bypass a missing RBAC grant)
"""

from database import get_db, get_user, get_resource, log_access
from rbac import check_rbac
from abac import evaluate_abac_policies


def evaluate(user_id, resource_id=None, resource_type=None, action=None, context=None):
    """
    Evaluate an access request and return a decision dict.

    Parameters
    ----------
    user_id       : int   – ID of the requesting user
    resource_id   : int   – ID of the specific resource (optional)
    resource_type : str   – resource type fallback when no resource_id given
    action        : str   – requested action (read/write/delete/share/send/admin)
    context       : dict  – optional context attributes (hour, device_type, login_location)

    Returns
    -------
    {
        "decision": "permit" | "deny",
        "reason":   str,
        "user":     str,
        "resource": str | None,
        "action":   str,
        "rbac":     str,
        "abac":     str,
    }
    """
    context = context or {}
    conn = get_db()

    try:
        # ── Resolve user ──────────────────────────────────────────────────
        user = get_user(user_id, conn)
        if not user:
            return _deny(f"User id={user_id} not found", action=action)

        # ── Resolve resource ──────────────────────────────────────────────
        resource = None
        if resource_id is not None:
            resource = get_resource(resource_id, conn)
            if not resource:
                return _deny(f"Resource id={resource_id} not found", action=action)
            rtype = resource["resource_type"]
            rname = resource["name"]
        else:
            rtype = resource_type
            rname = resource_type

        if not rtype:
            return _deny("No resource_type provided", action=action)

        # ── RBAC evaluation ───────────────────────────────────────────────
        rbac_permit, rbac_reason = check_rbac(user_id, rtype, action, conn)

        # ── ABAC evaluation ───────────────────────────────────────────────
        abac_explicit_permit, abac_deny, abac_reason = evaluate_abac_policies(
            user, resource, action, context, conn
        )

        # ── Combine decisions ─────────────────────────────────────────────
        if abac_deny:
            decision = "deny"
            final_reason = abac_reason
        elif not rbac_permit:
            decision = "deny"
            final_reason = rbac_reason
        else:
            decision = "permit"
            final_reason = f"{rbac_reason}; {abac_reason}"

        result = {
            "decision": decision,
            "reason":   final_reason,
            "user":     user["username"],
            "resource": rname,
            "action":   action,
            "rbac":     rbac_reason,
            "abac":     abac_reason,
        }

        log_access(user_id, resource_id, rtype, action, decision, final_reason, conn)
        return result

    finally:
        conn.close()


def _deny(reason, action=None):
    return {
        "decision": "deny",
        "reason":   reason,
        "user":     None,
        "resource": None,
        "action":   action,
        "rbac":     "N/A",
        "abac":     "N/A",
    }

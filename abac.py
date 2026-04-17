"""
Attribute-Based Access Control (ABAC) policy evaluation.

Each policy returns one of three outcomes:
  (explicit_permit=True,  explicit_deny=False, reason)  – ABAC grants
  (explicit_permit=False, explicit_deny=True,  reason)  – ABAC denies (overrides RBAC)
  (explicit_permit=False, explicit_deny=False, reason)  – no opinion (pass-through)
"""

from database import is_assigned
from rbac import get_user_roles


def evaluate_abac_policies(user, resource, action, context, conn):
    """
    Evaluate all ABAC policies in priority order.
    Returns (explicit_permit: bool, explicit_deny: bool, reason: str).
    """
    roles = get_user_roles(user["id"], conn)

    # ── Policy 1 ────────────────────────────────────────────────────────────
    # Employees can edit Google Docs ONLY if they own or are explicitly assigned.
    # Managers and admins are exempt from this restriction.
    if (
        action == "write"
        and resource is not None
        and resource["resource_type"] == "docs"
        and "employee" in roles
        and "manager" not in roles
        and "administrator" not in roles
    ):
        if resource["owner_id"] == user["id"]:
            return True, False, "ABAC: employee owns this document"
        if is_assigned(user["id"], resource["id"], conn):
            return True, False, "ABAC: employee is explicitly assigned to this document"
        return False, True, "ABAC: employee can only edit documents they own or are assigned to"

    # ── Policy 2 ────────────────────────────────────────────────────────────
    # Contractors can only read (no write / delete / share / send / admin).
    if "contractor" in roles and action in ("write", "delete", "share", "send", "admin"):
        return False, True, "ABAC: contractors are restricted to read-only access"

    # ── Policy 3 ────────────────────────────────────────────────────────────
    # Only managers (and admins) can share Google Drive files.
    if (
        action == "share"
        and resource is not None
        and resource["resource_type"] == "drive"
        and "employee" in roles
        and "manager" not in roles
        and "administrator" not in roles
    ):
        return False, True, "ABAC: only managers can share Drive files externally"

    # ── Policy 4 ────────────────────────────────────────────────────────────
    # Confidential documents require high clearance AND matching department.
    if resource is not None and resource["sensitivity_level"] == "confidential":
        if user["clearance_level"] != "high":
            return False, True, (
                f"ABAC: confidential resource requires high clearance "
                f"(user has '{user['clearance_level']}')"
            )
        if resource["department"] and user["department"] != resource["department"]:
            return False, True, (
                f"ABAC: confidential resource requires matching department "
                f"(resource: '{resource['department']}', user: '{user['department']}')"
            )

    # ── Policy 5 ────────────────────────────────────────────────────────────
    # Gmail send is only permitted from organizational accounts (@org.com).
    if (
        action == "send"
        and resource is not None
        and resource["resource_type"] == "gmail"
        and not user["email"].endswith("@org.com")
    ):
        return False, True, "ABAC: Gmail send requires an organizational account (@org.com)"

    # ── Policy 6 ────────────────────────────────────────────────────────────
    # Separation of Duties: auditors cannot grant permissions or perform admin actions.
    if action in ("share", "admin") and user["is_auditor"]:
        return False, True, (
            "ABAC: Separation of Duties — auditors cannot grant permissions or perform admin actions"
        )

    # ── Context-based policy ─────────────────────────────────────────────────
    # Contractors may only access resources during business hours (09:00–17:00).
    if context and "hour" in context and "contractor" in roles:
        hour = int(context["hour"])
        if not (9 <= hour < 17):
            return False, True, (
                f"ABAC: contractors can only access resources during business hours "
                f"(09:00–17:00); current hour is {hour:02d}:00"
            )

    return False, False, "ABAC: no policy restriction applied"

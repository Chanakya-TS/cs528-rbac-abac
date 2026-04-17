"""
Attribute-Based Access Control (ABAC) policy evaluation.

Each policy returns one of three outcomes:
  (explicit_permit=True,  explicit_deny=False, reason)  – ABAC grants
  (explicit_permit=False, explicit_deny=True,  reason)  – ABAC denies (overrides RBAC)
  (explicit_permit=False, explicit_deny=False, reason)  – no opinion (pass-through)

Policies
--------
 1. Employees may only write Docs they own or are explicitly assigned.
 2. Contractors are restricted to read and comment — no write/delete/share/send/admin.
 3. Contractors may only read/comment resources explicitly assigned to them.
 4. Only managers+ may share Drive files externally.
 5. Confidential resources require high clearance AND matching department.
 6. Gmail send requires an @org.com organisational account.
 7. SoD: auditors cannot grant permissions (share) or perform admin actions.
 8. Context — time: contractors may only access during business hours (09–17).
 9. Context — device: personal devices cannot access confidential resources.
10. Context — location: admin actions are not permitted from remote locations.
11. Context — location: remote access to confidential resources requires high clearance.
"""

from database import is_assigned
from rbac import get_user_roles


def evaluate_abac_policies(user, resource, action, context, conn):
    """
    Evaluate all ABAC policies in priority order.
    Returns (explicit_permit: bool, explicit_deny: bool, reason: str).
    """
    roles = get_user_roles(user["id"], conn)
    ctx   = context or {}

    # ── Policy 1 ─────────────────────────────────────────────────────────────
    # Employees can edit Google Docs ONLY if they own or are explicitly assigned.
    # Managers and admins are exempt.
    if (
        action == "write"
        and resource is not None
        and resource["resource_type"] == "docs"
        and "employee" in roles
        and "manager" not in roles
        and "administrator" not in roles
    ):
        if resource["owner_id"] == user["id"]:
            return True, False, "ABAC P1: employee owns this document"
        if is_assigned(user["id"], resource["id"], conn):
            return True, False, "ABAC P1: employee is explicitly assigned to this document"
        return False, True, "ABAC P1: employee can only edit documents they own or are assigned to"

    # ── Policy 2 ─────────────────────────────────────────────────────────────
    # Contractors are read/comment-only — no write, delete, share, send, or admin.
    if "contractor" in roles and action in ("write", "delete", "share", "send", "admin"):
        return False, True, "ABAC P2: contractors are restricted to read and comment only"

    # ── Policy 3 ─────────────────────────────────────────────────────────────
    # Contractors may only access resources that are explicitly assigned to them.
    if (
        "contractor" in roles
        and resource is not None
        and action in ("read", "comment")
        and resource["owner_id"] != user["id"]
        and not is_assigned(user["id"], resource["id"], conn)
    ):
        return False, True, "ABAC P3: contractors can only access resources assigned to them"

    # ── Policy 4 ─────────────────────────────────────────────────────────────
    # Only managers (and admins) can share Google Drive files.
    if (
        action == "share"
        and resource is not None
        and resource["resource_type"] == "drive"
        and "employee" in roles
        and "manager" not in roles
        and "administrator" not in roles
    ):
        return False, True, "ABAC P4: only managers can share Drive files externally"

    # ── Policy 5 ─────────────────────────────────────────────────────────────
    # Confidential documents require high clearance AND matching department.
    if resource is not None and resource["sensitivity_level"] == "confidential":
        if user["clearance_level"] != "high":
            return False, True, (
                f"ABAC P5: confidential resource requires high clearance "
                f"(user has '{user['clearance_level']}')"
            )
        if resource["department"] and user["department"] != resource["department"]:
            return False, True, (
                f"ABAC P5: confidential resource requires matching department "
                f"(resource: '{resource['department']}', user: '{user['department']}')"
            )

    # ── Policy 6 ─────────────────────────────────────────────────────────────
    # Gmail send is only permitted from organisational accounts (@org.com).
    if (
        action == "send"
        and resource is not None
        and resource["resource_type"] == "gmail"
        and not user["email"].endswith("@org.com")
    ):
        return False, True, "ABAC P6: Gmail send requires an organisational account (@org.com)"

    # ── Policy 7 ─────────────────────────────────────────────────────────────
    # Separation of Duties: auditors cannot grant permissions or perform admin actions.
    if action in ("share", "admin") and user["is_auditor"]:
        return False, True, (
            "ABAC P7: SoD — auditors cannot grant permissions or perform admin actions"
        )

    # ── Policy 8 ─────────────────────────────────────────────────────────────
    # Context — time: contractors may only access during business hours (09:00–17:00).
    if ctx.get("hour") is not None and "contractor" in roles:
        hour = int(ctx["hour"])
        if not (9 <= hour < 17):
            return False, True, (
                f"ABAC P8: contractors can only access resources during business hours "
                f"(09:00–17:00); current hour is {hour:02d}:00"
            )

    # ── Policy 9 ─────────────────────────────────────────────────────────────
    # Context — device: personal devices cannot access confidential resources.
    if (
        ctx.get("device_type", "").lower() == "personal"
        and resource is not None
        and resource["sensitivity_level"] == "confidential"
    ):
        return False, True, (
            "ABAC P9: confidential resources cannot be accessed from personal devices"
        )

    # ── Policy 10 ────────────────────────────────────────────────────────────
    # Context — location: admin actions are not permitted from remote locations.
    if ctx.get("login_location", "").lower() == "remote" and action == "admin":
        return False, True, "ABAC P10: admin actions are not permitted from remote locations"

    # ── Policy 11 ────────────────────────────────────────────────────────────
    # Context — location: remote access to confidential resources requires high clearance.
    if (
        ctx.get("login_location", "").lower() == "remote"
        and resource is not None
        and resource["sensitivity_level"] == "confidential"
        and user["clearance_level"] != "high"
    ):
        return False, True, (
            "ABAC P11: remote access to confidential resources requires high clearance "
            f"(user has '{user['clearance_level']}')"
        )

    return False, False, "ABAC: no policy restriction applied"

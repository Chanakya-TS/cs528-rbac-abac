"""Role-Based Access Control (RBAC) evaluation."""


def get_user_roles(user_id, conn):
    """Return list of role name strings for a user."""
    rows = conn.execute(
        """
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    return [row["name"] for row in rows]


def check_rbac(user_id, resource_type, action, conn):
    """
    Returns (permitted: bool, reason: str).
    Checks whether any of the user's roles grant the requested action
    on the given resource_type.
    """
    roles = get_user_roles(user_id, conn)
    if not roles:
        return False, "User has no assigned roles"

    for role in roles:
        row = conn.execute(
            """
            SELECT 1 FROM role_permissions
            WHERE role_name = ? AND resource_type = ? AND action = ?
            """,
            (role, resource_type, action),
        ).fetchone()
        if row:
            return True, f"Role '{role}' grants '{action}' on '{resource_type}'"

    return False, (
        f"No role among {roles} grants '{action}' on '{resource_type}'"
    )

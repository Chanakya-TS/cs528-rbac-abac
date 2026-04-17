"""
Role-Based Access Control (RBAC) evaluation.

RBAC1 — Role Hierarchy
    Roles form an inheritance chain: administrator → manager → employee.
    A senior role implicitly holds all permissions of its junior (parent) role.
    Hierarchy is resolved by walking the parent_role chain in the roles table.

RBAC2 — Constraints
    Static Separation of Duties: mutually-exclusive role pairs stored in
    role_exclusions prevent a user from holding conflicting roles simultaneously.
    Cardinality constraints (max_users on roles) cap the number of assignees.
"""


# ── Direct role lookup ─────────────────────────────────────────────────────────

def get_user_roles(user_id, conn):
    """Return the list of role names *directly* assigned to a user."""
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


# ── RBAC1: Hierarchy resolution ────────────────────────────────────────────────

def get_inherited_roles(role_name, conn, _visited=None):
    """
    RBAC1: Return ``role_name`` plus all ancestor roles it inherits from,
    walking the parent_role chain.  Cycle-safe via ``_visited``.

    Example: get_inherited_roles('administrator') →
             ['administrator', 'manager', 'employee']
    """
    if _visited is None:
        _visited = set()
    if role_name in _visited:
        return []
    _visited.add(role_name)

    result = [role_name]
    row = conn.execute(
        "SELECT parent_role FROM roles WHERE name = ?", (role_name,)
    ).fetchone()
    if row and row["parent_role"]:
        result.extend(get_inherited_roles(row["parent_role"], conn, _visited))
    return result


def get_all_effective_roles(user_id, conn):
    """
    Return every effective role name for a user — direct assignments plus all
    roles inherited via the RBAC1 hierarchy.
    """
    effective = set()
    for role in get_user_roles(user_id, conn):
        effective.update(get_inherited_roles(role, conn))
    return list(effective)


# ── RBAC permission check (hierarchy-aware) ────────────────────────────────────

def check_rbac(user_id, resource_type, action, conn):
    """
    RBAC1-aware permission check.

    Returns (permitted: bool, reason: str).
    Walks each directly-assigned role and its ancestors, checking role_permissions.
    """
    direct_roles = get_user_roles(user_id, conn)
    if not direct_roles:
        return False, "User has no assigned roles"

    for direct_role in direct_roles:
        for inherited_role in get_inherited_roles(direct_role, conn):
            row = conn.execute(
                """
                SELECT 1 FROM role_permissions
                WHERE role_name = ? AND resource_type = ? AND action = ?
                """,
                (inherited_role, resource_type, action),
            ).fetchone()
            if row:
                if inherited_role == direct_role:
                    return True, (
                        f"Role '{direct_role}' grants '{action}' on '{resource_type}'"
                    )
                else:
                    return True, (
                        f"Role '{direct_role}' inherits '{action}' on "
                        f"'{resource_type}' from '{inherited_role}'"
                    )

    return False, (
        f"No role among {direct_roles} (including inherited) "
        f"grants '{action}' on '{resource_type}'"
    )


# ── RBAC2: Constraint checks ───────────────────────────────────────────────────

def check_role_exclusions(user_id, new_role, conn):
    """
    RBAC2 Static SoD: ensure ``new_role`` does not conflict with any role
    the user already holds.

    Returns (allowed: bool, reason: str).
    """
    existing_roles = get_user_roles(user_id, conn)

    for existing in existing_roles:
        row = conn.execute(
            """
            SELECT reason FROM role_exclusions
            WHERE (role1 = ? AND role2 = ?) OR (role1 = ? AND role2 = ?)
            """,
            (existing, new_role, new_role, existing),
        ).fetchone()
        if row:
            return False, (
                f"RBAC2 SoD violation: '{new_role}' and '{existing}' are "
                f"mutually exclusive — {row['reason']}"
            )

    return True, "No exclusion constraint violated"


def check_role_cardinality(new_role, conn):
    """
    RBAC2 Cardinality: ensure assigning ``new_role`` does not exceed max_users.

    Returns (allowed: bool, reason: str).
    """
    role_row = conn.execute(
        "SELECT max_users FROM roles WHERE name = ?", (new_role,)
    ).fetchone()

    if not role_row or role_row["max_users"] is None:
        return True, "No cardinality limit on this role"

    count = conn.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE r.name = ?
        """,
        (new_role,),
    ).fetchone()["cnt"]

    if count >= role_row["max_users"]:
        return False, (
            f"RBAC2 cardinality violation: role '{new_role}' is at maximum "
            f"capacity ({count}/{role_row['max_users']} users)"
        )
    return True, f"Within cardinality limit ({count}/{role_row['max_users']})"

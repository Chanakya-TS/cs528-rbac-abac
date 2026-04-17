"""
Hybrid Access Control System — Flask Application

Endpoints
─────────
PEP (Policy Enforcement Point)
  POST /access                      Evaluate an access request

PAP (Policy Administration Point) — admin-only management
  GET  /admin/users                 List all users          [requires admin_id]
  POST /admin/users                 Create a new user
  GET  /admin/users/<id>            Get user details + roles
  POST /admin/users/<id>/role       Assign a role to a user (RBAC1 + RBAC2 checked)
  GET  /admin/roles                 List roles, hierarchy, and permissions
  POST /admin/permissions           Add a permission to a role
  GET  /admin/resources             List resources
  POST /admin/resources             Create a resource
  POST /admin/resources/<id>/assign Assign a resource to a user
  GET  /admin/logs                  View access logs        [requires admin_id]
  GET  /admin/constraints           List RBAC2 exclusion and cardinality constraints

Utility
  GET  /health                      Health check
"""

from flask import Flask, jsonify, request, abort, render_template
from database import get_db, init_db, reset_db, get_user, get_resource
from pdp import evaluate
from rbac import check_role_exclusions, check_role_cardinality, get_inherited_roles

app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_dict(row):
    return dict(row) if row else None


def _require_admin(conn, user_id):
    """Abort 403 if user_id is not an administrator."""
    if not user_id:
        abort(403, description="admin_id is required for this operation")
    roles = conn.execute(
        """
        SELECT r.name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    if not any(r["name"] == "administrator" for r in roles):
        abort(403, description="Administrator role required")


# ─────────────────────────────────────────────────────────────────────────────
# PEP — /access
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/access", methods=["POST"])
def access():
    """
    Policy Enforcement Point: intercepts an access request and returns
    a permit/deny decision from the PDP.

    Body (JSON)
    -----------
    {
        "user_id":       <int>,
        "resource_id":   <int>,          optional
        "resource_type": <str>,          required if no resource_id
        "action":        <str>,          read|write|comment|delete|share|send|admin
        "context": {                     optional
            "hour":           <int>,
            "device_type":    <str>,
            "login_location": <str>
        }
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    user_id       = data.get("user_id")
    resource_id   = data.get("resource_id")
    resource_type = data.get("resource_type")
    action        = data.get("action")
    context       = data.get("context", {})

    if user_id is None or action is None:
        return jsonify({"error": "user_id and action are required"}), 400
    if resource_id is None and resource_type is None:
        return jsonify({"error": "Either resource_id or resource_type is required"}), 400

    result = evaluate(
        user_id=int(user_id),
        resource_id=int(resource_id) if resource_id is not None else None,
        resource_type=resource_type,
        action=action,
        context=context,
    )
    status = 200 if result["decision"] == "permit" else 403
    return jsonify(result), status


# ─────────────────────────────────────────────────────────────────────────────
# PAP — Users
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/users", methods=["GET"])
def list_users():
    """List all users. Requires administrator (admin_id query param)."""
    admin_id = request.args.get("admin_id", type=int)
    conn = get_db()
    _require_admin(conn, admin_id)
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([_row_to_dict(r) for r in rows])


@app.route("/admin/users", methods=["POST"])
def create_user():
    """
    Create a new user.

    Body (JSON)
    -----------
    {
        "admin_id":        <int>,
        "username":        <str>,
        "email":           <str>,
        "employment_type": "full-time" | "contractor",
        "department":      <str>,
        "clearance_level": "low" | "medium" | "high",
        "is_auditor":      0 | 1   (optional, default 0)
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    _require_admin(conn, data.get("admin_id"))

    required = ("username", "email", "employment_type", "department", "clearance_level")
    for field in required:
        if not data.get(field):
            conn.close()
            return jsonify({"error": f"'{field}' is required"}), 400

    try:
        conn.execute(
            "INSERT INTO users (username, email, employment_type, department, clearance_level, is_auditor) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                data["username"],
                data["email"],
                data["employment_type"],
                data["department"],
                data["clearance_level"],
                int(data.get("is_auditor", 0)),
            ),
        )
        conn.commit()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (data["username"],)
        ).fetchone()
        conn.close()
        return jsonify(_row_to_dict(user)), 201
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


@app.route("/admin/users/<int:user_id>", methods=["GET"])
def get_user_detail(user_id):
    """Get user details including assigned roles."""
    conn = get_db()
    user = get_user(user_id, conn)
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    roles = conn.execute(
        """
        SELECT r.name, r.description, r.parent_role FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        """,
        (user_id,),
    ).fetchall()

    # Include full inherited role chain for each assigned role
    roles_with_inheritance = []
    for r in roles:
        inherited = get_inherited_roles(r["name"], conn)
        roles_with_inheritance.append({
            **_row_to_dict(r),
            "inherits": inherited[1:],  # exclude self
        })

    assignments = conn.execute(
        """
        SELECT res.id, res.name, res.resource_type FROM resources res
        JOIN resource_assignments ra ON res.id = ra.resource_id
        WHERE ra.user_id = ?
        """,
        (user_id,),
    ).fetchall()

    conn.close()
    return jsonify({
        **_row_to_dict(user),
        "roles": roles_with_inheritance,
        "assigned_resources": [_row_to_dict(a) for a in assignments],
    })


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def assign_role(user_id):
    """
    Assign a role to a user. Enforces RBAC2 constraints (SoD exclusions and
    cardinality) before committing the assignment.

    Body (JSON): { "admin_id": <int>, "role": <str> }
    """
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    _require_admin(conn, data.get("admin_id"))

    role_name = data.get("role", "").strip()
    if not role_name:
        conn.close()
        return jsonify({"error": "'role' is required"}), 400

    role = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
    if not role:
        conn.close()
        return jsonify({"error": f"Role '{role_name}' does not exist"}), 404

    user = get_user(user_id, conn)
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # ── RBAC2: Check exclusion constraints ───────────────────────────────────
    allowed, excl_reason = check_role_exclusions(user_id, role_name, conn)
    if not allowed:
        conn.close()
        return jsonify({"error": excl_reason}), 409

    # ── RBAC2: Check cardinality constraints ─────────────────────────────────
    allowed, card_reason = check_role_cardinality(role_name, conn)
    if not allowed:
        conn.close()
        return jsonify({"error": card_reason}), 409

    try:
        conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
            (user_id, role["id"]),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"Role '{role_name}' assigned to user {user_id}"}), 200
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────────────────────────────────────
# PAP — Roles & Permissions
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/roles", methods=["GET"])
def list_roles():
    """List all roles with hierarchy info and their permissions."""
    conn = get_db()
    roles = conn.execute("SELECT * FROM roles").fetchall()
    result = []
    for role in roles:
        # Own permissions
        perms = conn.execute(
            "SELECT resource_type, action FROM role_permissions WHERE role_name = ?",
            (role["name"],),
        ).fetchall()

        # Inherited permissions (from parent chain)
        inherited_chain = get_inherited_roles(role["name"], conn)[1:]  # skip self
        inherited_perms = []
        for ancestor in inherited_chain:
            ap = conn.execute(
                "SELECT resource_type, action FROM role_permissions WHERE role_name = ?",
                (ancestor,),
            ).fetchall()
            inherited_perms.extend([{**_row_to_dict(p), "from_role": ancestor} for p in ap])

        result.append({
            **_row_to_dict(role),
            "permissions":          [_row_to_dict(p) for p in perms],
            "inherited_permissions": inherited_perms,
            "hierarchy_chain":      get_inherited_roles(role["name"], conn),
        })
    conn.close()
    return jsonify(result)


@app.route("/admin/permissions", methods=["POST"])
def add_permission():
    """
    Add a permission to a role.

    Body (JSON):
    {
        "admin_id":      <int>,
        "role":          <str>,
        "resource_type": <str>,
        "action":        <str>
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    _require_admin(conn, data.get("admin_id"))

    for field in ("role", "resource_type", "action"):
        if not data.get(field):
            conn.close()
            return jsonify({"error": f"'{field}' is required"}), 400

    role = conn.execute("SELECT id FROM roles WHERE name = ?", (data["role"],)).fetchone()
    if not role:
        conn.close()
        return jsonify({"error": f"Role '{data['role']}' does not exist"}), 404

    try:
        conn.execute(
            "INSERT OR IGNORE INTO role_permissions (role_name, resource_type, action) VALUES (?, ?, ?)",
            (data["role"], data["resource_type"], data["action"]),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"Permission '{data['action']}' on '{data['resource_type']}' added to role '{data['role']}'" }), 201
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────────────────────────────────────
# PAP — Resources
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/resources", methods=["GET"])
def list_resources():
    """List all resources."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM resources").fetchall()
    conn.close()
    return jsonify([_row_to_dict(r) for r in rows])


@app.route("/admin/resources", methods=["POST"])
def create_resource():
    """
    Create a resource.

    Body (JSON):
    {
        "admin_id":         <int>,
        "name":             <str>,
        "resource_type":    "docs" | "gmail" | "drive" | "calendar",
        "owner_id":         <int>   (optional),
        "sensitivity_level":"public" | "internal" | "confidential",
        "department":       <str>   (optional)
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    _require_admin(conn, data.get("admin_id"))

    for field in ("name", "resource_type", "sensitivity_level"):
        if not data.get(field):
            conn.close()
            return jsonify({"error": f"'{field}' is required"}), 400

    try:
        conn.execute(
            "INSERT INTO resources (name, resource_type, owner_id, sensitivity_level, department) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                data["name"],
                data["resource_type"],
                data.get("owner_id"),
                data["sensitivity_level"],
                data.get("department"),
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM resources WHERE rowid = last_insert_rowid()"
        ).fetchone()
        conn.close()
        return jsonify(_row_to_dict(row)), 201
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


@app.route("/admin/resources/<int:resource_id>/assign", methods=["POST"])
def assign_resource(resource_id):
    """
    Explicitly assign a resource to a user.

    Body (JSON): { "admin_id": <int>, "user_id": <int> }
    """
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    _require_admin(conn, data.get("admin_id"))

    target_user = data.get("user_id")
    if not target_user:
        conn.close()
        return jsonify({"error": "'user_id' is required"}), 400

    try:
        conn.execute(
            "INSERT OR IGNORE INTO resource_assignments (user_id, resource_id) VALUES (?, ?)",
            (int(target_user), resource_id),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"Resource {resource_id} assigned to user {target_user}"}), 200
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


# ─────────────────────────────────────────────────────────────────────────────
# PAP — Access Logs (requires admin auth)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/logs", methods=["GET"])
def access_logs():
    """
    View access logs. Requires administrator (admin_id query param).
    Query params: limit (default 50), user_id, decision (permit|deny)
    """
    admin_id        = request.args.get("admin_id", type=int)
    conn            = get_db()
    _require_admin(conn, admin_id)

    limit           = request.args.get("limit", 50, type=int)
    user_filter     = request.args.get("user_id", type=int)
    decision_filter = request.args.get("decision")

    query  = "SELECT * FROM access_logs WHERE 1=1"
    params = []

    if user_filter:
        query += " AND user_id = ?"
        params.append(user_filter)
    if decision_filter:
        query += " AND decision = ?"
        params.append(decision_filter)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([_row_to_dict(r) for r in rows])


# ─────────────────────────────────────────────────────────────────────────────
# PAP — RBAC2 Constraints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin/constraints", methods=["GET"])
def list_constraints():
    """List all RBAC2 constraints: exclusions and cardinality limits."""
    conn = get_db()

    exclusions = conn.execute("SELECT * FROM role_exclusions").fetchall()
    cardinality = conn.execute(
        "SELECT name, max_users, description FROM roles WHERE max_users IS NOT NULL"
    ).fetchall()

    # Current counts per role
    counts = conn.execute(
        """
        SELECT r.name, COUNT(ur.user_id) AS current_count
        FROM roles r
        LEFT JOIN user_roles ur ON r.id = ur.role_id
        GROUP BY r.id
        """
    ).fetchall()
    count_map = {row["name"]: row["current_count"] for row in counts}

    conn.close()
    return jsonify({
        "exclusions": [_row_to_dict(e) for e in exclusions],
        "cardinality": [
            {
                **_row_to_dict(r),
                "current_count": count_map.get(r["name"], 0),
            }
            for r in cardinality
        ],
    })


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Hybrid Access Control System"})


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": str(e.description)}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e.description)}), 404


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    reset_db()
    init_db()
    print("Database initialised.")
    app.run(debug=True, port=5000)

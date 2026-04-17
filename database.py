import sqlite3

DB_PATH = "access_control.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        employment_type TEXT NOT NULL CHECK(employment_type IN ('full-time', 'contractor')),
        department TEXT NOT NULL,
        clearance_level TEXT NOT NULL CHECK(clearance_level IN ('low', 'medium', 'high')),
        is_auditor INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS user_roles (
        user_id INTEGER NOT NULL,
        role_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (role_id) REFERENCES roles(id)
    );

    CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        resource_type TEXT NOT NULL CHECK(resource_type IN ('docs', 'gmail', 'drive', 'calendar')),
        owner_id INTEGER,
        sensitivity_level TEXT NOT NULL CHECK(sensitivity_level IN ('public', 'internal', 'confidential')),
        department TEXT,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS resource_assignments (
        user_id INTEGER NOT NULL,
        resource_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, resource_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (resource_id) REFERENCES resources(id)
    );

    CREATE TABLE IF NOT EXISTS role_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        action TEXT NOT NULL,
        UNIQUE(role_name, resource_type, action)
    );

    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        resource_id INTEGER,
        resource_type TEXT,
        action TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('permit', 'deny')),
        reason TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)

    # ── Roles ──────────────────────────────────────────────────────────────
    roles = [
        ("administrator", "Full control over users, permissions, and services"),
        ("manager",       "Manage team resources, approve access, and share documents"),
        ("employee",      "Create and edit documents, send emails, and collaborate"),
        ("contractor",    "Limited access to assigned documents and tools"),
        ("viewer",        "Read-only access to shared resources"),
    ]
    c.executemany("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", roles)

    # ── RBAC permission matrix ─────────────────────────────────────────────
    permissions = [
        # administrator — full access
        ("administrator", "docs",     "read"),
        ("administrator", "docs",     "write"),
        ("administrator", "docs",     "delete"),
        ("administrator", "docs",     "share"),
        ("administrator", "gmail",    "read"),
        ("administrator", "gmail",    "write"),
        ("administrator", "gmail",    "delete"),
        ("administrator", "gmail",    "send"),
        ("administrator", "drive",    "read"),
        ("administrator", "drive",    "write"),
        ("administrator", "drive",    "delete"),
        ("administrator", "drive",    "share"),
        ("administrator", "calendar", "read"),
        ("administrator", "calendar", "write"),
        ("administrator", "calendar", "delete"),
        ("administrator", "calendar", "send"),
        ("administrator", "system",   "admin"),
        # manager
        ("manager", "docs",     "read"),
        ("manager", "docs",     "write"),
        ("manager", "docs",     "delete"),
        ("manager", "docs",     "share"),
        ("manager", "gmail",    "read"),
        ("manager", "gmail",    "write"),
        ("manager", "gmail",    "send"),
        ("manager", "drive",    "read"),
        ("manager", "drive",    "write"),
        ("manager", "drive",    "delete"),
        ("manager", "drive",    "share"),
        ("manager", "calendar", "read"),
        ("manager", "calendar", "write"),
        ("manager", "calendar", "send"),
        # employee
        ("employee", "docs",     "read"),
        ("employee", "docs",     "write"),
        ("employee", "gmail",    "read"),
        ("employee", "gmail",    "write"),
        ("employee", "gmail",    "send"),
        ("employee", "drive",    "read"),
        ("employee", "drive",    "write"),
        ("employee", "calendar", "read"),
        ("employee", "calendar", "write"),
        ("employee", "calendar", "send"),
        # contractor — read only
        ("contractor", "docs",     "read"),
        ("contractor", "drive",    "read"),
        ("contractor", "calendar", "read"),
        # viewer — read only
        ("viewer", "docs",     "read"),
        ("viewer", "drive",    "read"),
        ("viewer", "gmail",    "read"),
        ("viewer", "calendar", "read"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO role_permissions (role_name, resource_type, action) VALUES (?, ?, ?)",
        permissions,
    )

    # ── Sample users ───────────────────────────────────────────────────────
    # (id, username, email, employment_type, department, clearance_level, is_auditor)
    users = [
        (1, "alice_admin",     "alice@org.com",  "full-time",  "IT",          "high",   0),
        (2, "bob_manager",     "bob@org.com",    "full-time",  "Engineering", "high",   0),
        (3, "carol_employee",  "carol@org.com",  "full-time",  "Engineering", "medium", 0),
        (4, "dave_contractor", "dave@ext.com",   "contractor", "Engineering", "low",    0),
        (5, "eve_viewer",      "eve@org.com",    "full-time",  "Marketing",   "low",    0),
        (6, "frank_auditor",   "frank@org.com",  "full-time",  "Compliance",  "medium", 1),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users "
        "(id, username, email, employment_type, department, clearance_level, is_auditor) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        users,
    )

    # ── User-role assignments ──────────────────────────────────────────────
    user_role_map = [
        (1, "administrator"),
        (2, "manager"),
        (3, "employee"),
        (4, "contractor"),
        (5, "viewer"),
        (6, "employee"),
    ]
    for uid, rname in user_role_map:
        row = c.execute("SELECT id FROM roles WHERE name = ?", (rname,)).fetchone()
        if row:
            c.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (uid, row["id"]),
            )

    # ── Sample resources ───────────────────────────────────────────────────
    # (id, name, resource_type, owner_id, sensitivity_level, department)
    resources = [
        (1, "Q1 Engineering Report",     "docs",     3,    "internal",     "Engineering"),
        (2, "Confidential Strategy Doc", "docs",     2,    "confidential", "Engineering"),
        (3, "Public Announcement",       "docs",     1,    "public",       None),
        (4, "Engineering Drive",         "drive",    2,    "internal",     "Engineering"),
        (5, "Public Shared Drive",       "drive",    1,    "public",       None),
        (6, "Org Inbox",                 "gmail",    None, "internal",     None),
        (7, "Team Calendar",             "calendar", 2,    "internal",     "Engineering"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO resources "
        "(id, name, resource_type, owner_id, sensitivity_level, department) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        resources,
    )

    # Explicitly assign contractor (dave, id=4) to the Q1 report (id=1)
    c.execute(
        "INSERT OR IGNORE INTO resource_assignments (user_id, resource_id) VALUES (?, ?)",
        (4, 1),
    )

    conn.commit()
    conn.close()


# ── Helper getters ─────────────────────────────────────────────────────────

def get_user(user_id, conn):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_resource(resource_id, conn):
    return conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()


def is_assigned(user_id, resource_id, conn):
    row = conn.execute(
        "SELECT 1 FROM resource_assignments WHERE user_id = ? AND resource_id = ?",
        (user_id, resource_id),
    ).fetchone()
    return row is not None


def log_access(user_id, resource_id, resource_type, action, decision, reason, conn):
    conn.execute(
        "INSERT INTO access_logs (user_id, resource_id, resource_type, action, decision, reason) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, resource_id, resource_type, action, decision, reason),
    )
    conn.commit()

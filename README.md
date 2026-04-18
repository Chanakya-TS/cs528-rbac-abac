# Hybrid Access Control System — CS 528 GP4

A Python/Flask web application implementing a hybrid **RBAC + ABAC** access control system for a cloud-based Google Workspace domain. The project combines RBAC1 role hierarchy, RBAC2 static constraints, 11 ABAC policies, PAP/PDP/PEP architecture, audit logging, a PDF report generator, and an interactive web UI for testing policy decisions.

---

## Requirements

- Python 3.10+
- pip

If `python` is not recognized, see the [Adding Python to PATH](#adding-python-to-path-one-time-fix) section below.

---

## Setup & Run

### 1. Open Command Prompt or PowerShell

Navigate to the project folder:

```
cd path\to\cs528-rbac-abac
```

### 2. Install dependencies

```
python -m pip install flask reportlab
```

or:

```
python -m pip install -r requirements.txt
```

### 3. Run the app

```
python app.py
```

The database is reset, recreated, and seeded on every startup. This means each run starts from the same known demo state, including seeded users, roles, resources, hierarchy data, RBAC2 constraints, and sample assignments.

### 4. Open the UI

Go to **http://127.0.0.1:5000** in your browser.

To stop the server, press `Ctrl+C` in the terminal.

---

## Generating the PDF Report

```
python generate_report.py
```

Output: `report.pdf` in the project folder.

---

## Adding Python to PATH (one-time fix)

If `python` is not recognized after installing Python:

1. Search **"Edit the system environment variables"** in the Start menu
2. Click **Environment Variables...**
3. Under **User variables**, select **Path** → **Edit**
4. Click **New** and add the path to your Python install, e.g.:
   `C:\Users\<YourName>\AppData\Local\Programs\Python\Python313`
5. Click **New** again and add the Scripts folder, e.g.:
   `C:\Users\<YourName>\AppData\Local\Programs\Python\Python313\Scripts`
6. Click OK on all windows and reopen Command Prompt

> **Tip:** To find your Python install location, run `where python` or `py -0p` in Command Prompt.

---

## Project Structure

```
cs528-rbac-abac/
├── app.py              # Flask app — PAP endpoints + PEP (/access)
├── pdp.py              # Policy Decision Point — combines RBAC + ABAC
├── rbac.py             # RBAC1 hierarchy resolution + RBAC2 constraint checks
├── abac.py             # 11 ABAC policy rules
├── database.py         # SQLite schema, seed data, helpers
├── generate_report.py  # Generates report.pdf
├── report.pdf          # Project report (5 pages)
├── requirements.txt
└── templates/
    └── index.html      # Web UI (simulator, users, roles, constraints, logs)
```

---

## Seeded Users

| ID | Username        | Role          | Clearance | Notes          |
|----|-----------------|---------------|-----------|----------------|
| 1  | alice_admin     | administrator | high      | Default admin  |
| 2  | bob_manager     | manager       | high      |                |
| 3  | carol_employee  | employee      | medium    |                |
| 4  | dave_contractor | contractor    | low       | Assigned to resource #1 |
| 5  | eve_viewer      | viewer        | low       |                |
| 6  | frank_auditor   | employee      | medium    | is_auditor = 1 |

**Admin session:** The UI defaults to `alice_admin` (ID 1). Admin-gated operations such as listing users, creating users, assigning roles, adding permissions, and viewing logs require an administrator session selected in the header.

---

## Key Features

- **RBAC1** — Role hierarchy: administrator → manager → employee. Senior roles inherit all junior permissions automatically.
- **RBAC2** — Static SoD exclusions (e.g. manager ⊗ contractor) and cardinality limits (max 5 admins, 20 contractors) enforced at role assignment.
- **11 ABAC Policies** — Ownership, clearance, department matching, org email, separation of duties, time-of-day, device type, and login location.
- **PAP/PDP/PEP** — Clean separation: admin REST API (PAP), `pdp.py` decision engine (PDP), `/access` endpoint (PEP).
- **Audit Logging** — Every access decision logged; viewable only by admins.
- **Interactive UI** — 18 one-click demo scenarios, role hierarchy tree, RBAC2 constraint viewer, user registration with role assignment, and live permission matrix.

---

## Architecture

The code follows a standard policy architecture:

- **PEP**: `POST /access` receives an access request from the UI or API caller
- **PDP**: `pdp.py` combines RBAC and ABAC evaluation into a final `permit` or `deny`
- **PAP**: `/admin/*` endpoints manage users, roles, permissions, assignments, constraints, and logs

Decision flow:

1. Resolve the requesting user and target resource
2. Evaluate RBAC permissions, including inherited permissions from the RBAC1 hierarchy
3. Evaluate ABAC policies using user, resource, and contextual attributes
4. Apply final decision logic: ABAC deny overrides, RBAC must still allow the action
5. Log the result to `access_logs`

The final response includes both the overall decision and separate RBAC/ABAC reason strings so the result is explainable during demos.

---

## RBAC Model

### RBAC1 Hierarchy

The role hierarchy is implemented in the `roles.parent_role` column and resolved in rbac.py:

- `administrator -> manager -> employee`

This means:

- administrators inherit manager permissions
- managers inherit employee permissions
- contractors and viewers remain isolated roles with no parent

The hierarchy is surfaced in both the API and the UI:

- `/admin/roles` returns each role's own permissions, inherited permissions, and full hierarchy chain
- the Roles & Hierarchy tab renders the hierarchy tree and a permission matrix showing direct vs inherited permissions

### RBAC2 Constraints

RBAC2 is enforced when assigning roles in `POST /admin/users/<id>/role`.

Current static separation-of-duty exclusions are seeded in database.py:

- `administrator` and `contractor`
- `manager` and `contractor`
- `employee` and `contractor`
- `viewer` and `contractor`

Current role cardinality limits:

- `administrator`: max 5 users
- `contractor`: max 20 users

The UI exposes these through the RBAC2 Constraints tab, and the API exposes them through:

- `GET /admin/constraints`

---

## ABAC Policies

The branch currently implements 11 ABAC policies in abac.py:

1. Employees may only write Docs they own or are explicitly assigned.
2. Contractors are restricted to read and comment only.
3. Contractors may only access resources explicitly assigned to them.
4. Only managers and administrators may share Drive files.
5. Confidential resources require high clearance and matching department.
6. Gmail send requires an `@org.com` account.
7. Auditors cannot perform `share` or `admin` actions.
8. Contractors may only access resources during business hours (`09:00-17:00`) when `context.hour` is provided.
9. Personal devices cannot access confidential resources.
10. Admin actions are not permitted from remote locations.
11. Remote access to confidential resources requires high clearance.

Context attributes accepted by the access API:

- `hour`
- `device_type`
- `login_location`

---

## Actions and Resource Types

The system models common Google Workspace-style resources:

- `docs`
- `gmail`
- `drive`
- `calendar`
- `system` for administrative actions

Supported actions in this branch include:

- `read`
- `write`
- `comment`
- `delete`
- `share`
- `send`
- `admin`

The `comment` action is part of this branch's permission model and is shown in the UI, RBAC matrix, ABAC logic, and report generator.

---

## Main Endpoints

### Access Evaluation

- `POST /access`

Example payload:

```json
{
  "user_id": 3,
  "resource_id": 1,
  "action": "write",
  "context": {
    "hour": 14,
    "device_type": "corporate",
    "login_location": "office"
  }
}
```

Returns JSON such as:

```json
{
  "decision": "permit",
  "reason": "Role 'employee' grants 'write' on 'docs'; ABAC: no policy restriction applied",
  "user": "carol_employee",
  "resource": "Q1 Engineering Report",
  "action": "write",
  "rbac": "Role 'employee' grants 'write' on 'docs'",
  "abac": "ABAC: no policy restriction applied"
}
```

### PAP / Admin API

Current endpoints in app.py:

- `GET /admin/users` requires `admin_id`
- `POST /admin/users` requires `admin_id`
- `GET /admin/users/<id>`
- `POST /admin/users/<id>/role` requires `admin_id`
- `GET /admin/roles`
- `POST /admin/permissions` requires `admin_id`
- `GET /admin/resources`
- `POST /admin/resources` requires `admin_id`
- `POST /admin/resources/<id>/assign` requires `admin_id`
- `GET /admin/logs` requires `admin_id`
- `GET /admin/constraints`
- `GET /health`

This branch protects user listing, writes, and log access with administrator checks, while some read-only metadata endpoints remain directly accessible for the UI.

---

## Web UI

The single-page interface in templates/index.html includes these major views:

- Simulator
- Users
- Register User
- Resources
- Roles & Hierarchy
- Add Permission
- RBAC2 Constraints
- Access Logs

Notable UI features implemented in this branch:

- acting-as admin session selector in the header
- quick scenario buttons for one-click demos
- optional context fields for time, device type, and location
- live decision explanation showing both RBAC and ABAC reasoning
- inline role assignment from the Users table
- role hierarchy visualization and inherited-permission matrix
- constraint tables for SoD exclusions and cardinality limits

---

## Demo Data and Startup Behavior

On startup, `app.py` calls:

1. `reset_db()`
2. `init_db()`

This recreates the schema and reseeds:

- users
- roles
- hierarchy metadata
- exclusion constraints
- role permissions
- resources
- one explicit contractor resource assignment

That behavior is useful for repeatable demos, but it also means any users, permissions, resources, or logs you add during a session will be cleared the next time the server starts.

---

## Report Generation

generate_report.py uses `reportlab` to generate `report.pdf`. The script summarizes:

- PAP/PDP/PEP architecture
- request evaluation flow
- RBAC permission matrix
- ABAC policy table
- RBAC2 exclusions and cardinality limits
- demo scenarios and implementation notes

This makes the repository usable both as a runnable app and as a class submission artifact.

---

## Notes

- The checked-in `access_control.db` may not reflect the latest schema until the app is run, because the schema is rebuilt at startup.
- The project is demo-oriented: identity is selected in the UI rather than authenticated through login/session middleware.

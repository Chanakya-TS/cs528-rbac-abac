# Hybrid Access Control System — CS 528 GP4

A Python/Flask web application implementing a hybrid **RBAC + ABAC** access control system for a cloud-based Google Workspace domain. Features RBAC1 role hierarchy, RBAC2 static constraints, 11 ABAC policies, PAP/PDP/PEP architecture, and an interactive web UI.

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
cd path\to\cs428_lastproj
```

### 2. Install dependencies

```
python -m pip install flask reportlab
```

### 3. Run the app

```
python app.py
```

The database is automatically created and seeded on every startup.

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
cs428_lastproj/
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

**Admin session:** The UI defaults to `alice_admin` (ID 1). All admin operations (users, logs, permissions) require an admin session selected in the header.

---

## Key Features

- **RBAC1** — Role hierarchy: administrator → manager → employee. Senior roles inherit all junior permissions automatically.
- **RBAC2** — Static SoD exclusions (e.g. manager ⊗ contractor) and cardinality limits (max 5 admins, 20 contractors) enforced at role assignment.
- **11 ABAC Policies** — Ownership, clearance, department matching, org email, separation of duties, time-of-day, device type, and login location.
- **PAP/PDP/PEP** — Clean separation: admin REST API (PAP), `pdp.py` decision engine (PDP), `/access` endpoint (PEP).
- **Audit Logging** — Every access decision logged; viewable only by admins.
- **Interactive UI** — 18 one-click demo scenarios, role hierarchy tree, RBAC2 constraint viewer, user registration with role assignment, and live permission matrix.

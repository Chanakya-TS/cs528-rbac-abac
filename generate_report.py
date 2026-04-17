"""
Generate the CS 528 GP4 project report as a PDF.
Run:  python generate_report.py
Output: report.pdf
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import reportlab.lib.colors as rlc

# ── Colour palette ─────────────────────────────────────────────────────────────
DARK_BG    = rlc.HexColor("#1a1d27")
ACCENT     = rlc.HexColor("#4f6ef7")
GREEN      = rlc.HexColor("#22c55e")
RED        = rlc.HexColor("#ef4444")
YELLOW     = rlc.HexColor("#f59e0b")
MUTED      = rlc.HexColor("#8892a4")
BORDER     = rlc.HexColor("#2e3350")
LIGHT_BLUE = rlc.HexColor("#dbeafe")
LIGHT_GRN  = rlc.HexColor("#dcfce7")
LIGHT_RED  = rlc.HexColor("#fee2e2")
LIGHT_YEL  = rlc.HexColor("#fef9c3")
WHITE      = colors.white
BLACK      = colors.black
ALMOST_BLK = rlc.HexColor("#1e293b")

# ── Styles ─────────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle("ReportTitle",
        fontName="Helvetica-Bold", fontSize=22, leading=28,
        textColor=ALMOST_BLK, alignment=TA_CENTER, spaceAfter=6)

    subtitle = ParagraphStyle("Subtitle",
        fontName="Helvetica", fontSize=12, leading=16,
        textColor=MUTED, alignment=TA_CENTER, spaceAfter=4)

    h1 = ParagraphStyle("H1",
        fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=ACCENT, spaceBefore=18, spaceAfter=6,
        borderPad=4)

    h2 = ParagraphStyle("H2",
        fontName="Helvetica-Bold", fontSize=11, leading=14,
        textColor=ALMOST_BLK, spaceBefore=12, spaceAfter=4)

    body = ParagraphStyle("Body",
        fontName="Helvetica", fontSize=9.5, leading=14,
        textColor=ALMOST_BLK, alignment=TA_JUSTIFY, spaceAfter=6)

    code = ParagraphStyle("Code",
        fontName="Courier", fontSize=8.5, leading=12,
        textColor=ALMOST_BLK, spaceAfter=4, leftIndent=12)

    bullet = ParagraphStyle("Bullet",
        fontName="Helvetica", fontSize=9.5, leading=14,
        textColor=ALMOST_BLK, leftIndent=16, spaceAfter=3,
        bulletIndent=6)

    caption = ParagraphStyle("Caption",
        fontName="Helvetica-Oblique", fontSize=8.5, leading=12,
        textColor=MUTED, alignment=TA_CENTER, spaceAfter=8)

    return dict(title=title, subtitle=subtitle, h1=h1, h2=h2,
                body=body, code=code, bullet=bullet, caption=caption)

S = make_styles()


def hr(): return HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=8, spaceBefore=4)

def sp(h=6): return Spacer(1, h)

def P(text, style="body"): return Paragraph(text, S[style])

def bullet(text): return Paragraph(f"• {text}", S["bullet"])


# ── Architecture ASCII diagram as a table ─────────────────────────────────────

def arch_table():
    """Render the PAP / PDP / PEP architecture as a formatted table diagram."""
    style = TableStyle([
        ('BOX',        (0,0), (-1,-1), 1.2, BORDER),
        ('INNERGRID',  (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,0), (0,-1),  LIGHT_BLUE),
        ('BACKGROUND', (1,0), (1,-1),  LIGHT_GRN),
        ('BACKGROUND', (2,0), (2,-1),  LIGHT_YEL),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME',   (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME',   (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [None, None]),
        ('TOPPADDING',  (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
    ])

    data = [
        [
            Paragraph("<b>PAP</b>\nPolicy Administration Point", S["body"]),
            Paragraph("<b>PDP</b>\nPolicy Decision Point",       S["body"]),
            Paragraph("<b>PEP</b>\nPolicy Enforcement Point",    S["body"]),
        ],
        [
            Paragraph("Admin defines roles,\npermissions, users,\nresources &amp; ABAC rules\nvia REST API / UI", S["body"]),
            Paragraph("Combines RBAC1\nhierarchy + 11 ABAC\npolicies → permit/deny\ndecision + reason", S["body"]),
            Paragraph("Flask /access endpoint\nintercepts requests,\ncalls PDP, returns\ndecision to client", S["body"]),
        ],
        [
            Paragraph("Flask PAP endpoints\n/admin/*", S["code"]),
            Paragraph("pdp.py → rbac.py\n+ abac.py", S["code"]),
            Paragraph("POST /access\nFlask + index.html", S["code"]),
        ],
    ]

    return Table(data, colWidths=[2.1*inch, 2.1*inch, 2.1*inch], style=style)


def data_flow_table():
    """Show the request evaluation flow as a numbered sequence."""
    style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('LINEBELOW',   (0,0), (-1,-2), 0.5, BORDER),
        ('BACKGROUND',  (0,0), (0,-1), LIGHT_BLUE),
        ('ALIGN',       (0,0), (0,-1), 'CENTER'),
        ('ALIGN',       (1,0), (1,-1), 'LEFT'),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 9),
        ('TOPPADDING',  (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING', (1,0), (1,-1), 10),
    ])

    steps = [
        ("1", "Client sends POST /access with user_id, resource_id, action, context"),
        ("2", "PEP (Flask) validates input, forwards to PDP evaluate()"),
        ("3", "PDP resolves user attributes (dept, clearance, is_auditor) from SQLite"),
        ("4", "PDP calls check_rbac() — walks RBAC1 hierarchy for inherited permissions"),
        ("5", "PDP calls evaluate_abac_policies() — evaluates all 11 policies in order"),
        ("6", "Decision logic: ABAC deny > RBAC deny > permit; reason string assembled"),
        ("7", "Access event logged to access_logs table (user, resource, decision, reason)"),
        ("8", "JSON response { decision, reason, user, resource, rbac, abac } returned"),
    ]

    data = [[Paragraph(f"<b>{s}</b>", S["body"]),
             Paragraph(t, S["body"])] for s, t in steps]
    return Table(data, colWidths=[0.35*inch, 5.85*inch], style=style)


def rbac_matrix_table():
    """Permission matrix for all roles (including inherited)."""
    style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('INNERGRID',   (0,0), (-1,-1), 0.4, BORDER),
        ('BACKGROUND',  (0,0), (-1, 0), DARK_BG),
        ('TEXTCOLOR',   (0,0), (-1, 0), WHITE),
        ('FONTNAME',    (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME',    (0,1), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 8),
        ('ALIGN',       (1,0), (-1,-1), 'CENTER'),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        # Alternating rows
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, rlc.HexColor("#f8fafc")]),
    ])

    actions = ["read", "write", "comment", "delete", "share", "send", "admin"]
    header  = ["Role / Resource"] + actions

    # Own + inherited full sets (manually computed to match code)
    # administrator inherits manager which inherits employee
    admin_perms = {
        "docs":     {"read","write","comment","delete","share"},
        "gmail":    {"read","write","send","delete"},
        "drive":    {"read","write","comment","delete","share"},
        "calendar": {"read","write","send","delete"},
        "system":   {"admin"},
    }
    manager_perms = {
        "docs":     {"read","write","comment","delete","share"},
        "gmail":    {"read","write","send"},
        "drive":    {"read","write","comment","delete","share"},
        "calendar": {"read","write","send"},
        "system":   set(),
    }
    employee_perms = {
        "docs":     {"read","write","comment"},
        "gmail":    {"read","write","send"},
        "drive":    {"read","write","comment"},
        "calendar": {"read","write","send"},
        "system":   set(),
    }
    contractor_perms = {
        "docs":     {"read","comment"},
        "drive":    {"read"},
        "calendar": {"read"},
    }
    viewer_perms = {
        "docs":     {"read","comment"},
        "gmail":    {"read"},
        "drive":    {"read"},
        "calendar": {"read"},
    }

    resource_types = ["docs", "gmail", "drive", "calendar", "system"]

    def row(role_name, pmap, bg):
        rows = []
        for rt in resource_types:
            rt_perms = pmap.get(rt, set())
            cells = [Paragraph(f"<b>{role_name}</b> / {rt}", S["code"])]
            for a in actions:
                cells.append("✓" if a in rt_perms else "·")
            rows.append(cells)
        return rows

    data = [header]
    data += row("admin",      admin_perms,      LIGHT_BLUE)
    data += row("manager",    manager_perms,    LIGHT_GRN)
    data += row("employee",   employee_perms,   LIGHT_YEL)
    data += row("contractor", contractor_perms, LIGHT_RED)
    data += row("viewer",     viewer_perms,     WHITE)

    # Colour stripes per role group
    starts = [1, 6, 11, 16, 21]
    bgs    = [LIGHT_BLUE, LIGHT_GRN, LIGHT_YEL, LIGHT_RED, WHITE]
    for s, bg in zip(starts, bgs):
        style.add('BACKGROUND', (0, s), (-1, s + 4), bg)

    return Table(data, colWidths=[1.3*inch] + [0.72*inch]*7, style=style)


def abac_policy_table():
    style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('LINEBELOW',   (0,0), (-1,-2), 0.4, BORDER),
        ('BACKGROUND',  (0,0), (-1, 0), DARK_BG),
        ('TEXTCOLOR',   (0,0), (-1, 0), WHITE),
        ('FONTNAME',    (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 8.5),
        ('VALIGN',      (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',  (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, rlc.HexColor("#f8fafc")]),
    ])

    policies = [
        ("#", "Policy", "Attribute Type", "Effect"),
        ("P1",  "Employee may write Docs only if owner or explicitly assigned",
         "User role + Resource owner/assignment", "Permit / Deny"),
        ("P2",  "Contractors: read and comment only — no write/delete/share/send/admin",
         "User role (contractor)",                "Deny"),
        ("P3",  "Contractors may only access resources assigned to them",
         "User role + Resource assignment",       "Deny"),
        ("P4",  "Only managers+ may share Drive files",
         "User role",                             "Deny"),
        ("P5",  "Confidential resources require high clearance + matching department",
         "User clearance &amp; dept + Resource sensitivity/dept", "Deny"),
        ("P6",  "Gmail send only from @org.com accounts",
         "User email domain",                     "Deny"),
        ("P7",  "SoD: auditors cannot share or admin",
         "User is_auditor flag",                  "Deny"),
        ("P8",  "Contractors: business hours only (09:00–17:00)",
         "Context: hour",                         "Deny"),
        ("P9",  "Personal devices cannot access confidential resources",
         "Context: device_type",                  "Deny"),
        ("P10", "Remote login cannot perform admin actions",
         "Context: login_location",               "Deny"),
        ("P11", "Remote + confidential requires high clearance",
         "Context: login_location + User clearance", "Deny"),
    ]

    data = [[Paragraph(f"<b>{c}</b>" if i==0 else c, S["body"]) for c in row]
            for i, row in enumerate(policies)]
    return Table(data, colWidths=[0.3*inch, 2.6*inch, 2.2*inch, 0.7*inch], style=style)


def rbac2_table():
    style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('LINEBELOW',   (0,0), (-1,-2), 0.4, BORDER),
        ('BACKGROUND',  (0,0), (-1, 0), DARK_BG),
        ('TEXTCOLOR',   (0,0), (-1, 0), WHITE),
        ('FONTNAME',    (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 8.5),
        ('VALIGN',      (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',  (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, rlc.HexColor("#f8fafc")]),
    ])

    rows = [
        ["Type", "Constraint", "Detail"],
        ["SoD Exclusion", "administrator ⊗ contractor", "Privilege escalation risk"],
        ["SoD Exclusion", "manager ⊗ contractor",       "Conflict of interest"],
        ["SoD Exclusion", "employee ⊗ contractor",      "Mutually exclusive roles"],
        ["SoD Exclusion", "viewer ⊗ contractor",        "Assign only one"],
        ["SoD (ABAC P7)", "auditor cannot share/admin", "Role attribute + action guard"],
        ["Cardinality",   "administrator: max 5 users", "Limit blast radius of admins"],
        ["Cardinality",   "contractor: max 20 users",   "Cap third-party exposure"],
    ]

    data = [[Paragraph(f"<b>{c}</b>" if i==0 else c, S["body"]) for c in row]
            for i, row in enumerate(rows)]
    return Table(data, colWidths=[1.3*inch, 2.5*inch, 2.0*inch], style=style)


# ── Build PDF ──────────────────────────────────────────────────────────────────

def build():
    doc = SimpleDocTemplate(
        "report.pdf",
        pagesize=letter,
        leftMargin=0.85*inch, rightMargin=0.85*inch,
        topMargin=0.9*inch,   bottomMargin=0.9*inch,
    )

    story = []

    # ── Title page ────────────────────────────────────────────────────────────
    story += [
        sp(30),
        P("Hybrid Access Control System", "title"),
        P("for Cloud-Based Productivity Services", "title"),
        sp(10),
        P("CS 428/528 — Computer Security &nbsp;|&nbsp; Group Project 4", "subtitle"),
        P("Domain: Google Workspace (Docs · Gmail · Drive · Calendar)", "subtitle"),
        sp(4),
        P("Apr 17, 2026", "subtitle"),
        sp(30),
        hr(),
        sp(8),
    ]

    # ── 1. System Architecture ────────────────────────────────────────────────
    story += [
        P("1. System Architecture", "h1"),
        P(
            "The system implements a standard <b>PAP → PDP → PEP</b> policy-based access control "
            "architecture on top of a Python/Flask web application backed by SQLite. "
            "RBAC1 (role hierarchy) and ABAC attribute evaluation are combined inside the PDP "
            "to produce a single permit/deny decision for every access request.",
            "body"
        ),
        sp(6),
        arch_table(),
        P("Figure 1 — Three-tier policy architecture (PAP · PDP · PEP)", "caption"),
        sp(10),
    ]

    story += [
        P("1.1 Request Evaluation Flow", "h2"),
        data_flow_table(),
        P("Figure 2 — Step-by-step access decision sequence", "caption"),
        sp(6),
        P(
            "The SQLite database stores six tables: <i>users, roles, user_roles, resources, "
            "resource_assignments, role_permissions, role_exclusions,</i> and <i>access_logs</i>. "
            "All RBAC data (hierarchy, exclusions, cardinality limits) is kept in the DB; "
            "ABAC policy logic lives purely in <code>abac.py</code>.",
            "body"
        ),
    ]

    # ── 2. Domain ─────────────────────────────────────────────────────────────
    story += [
        hr(),
        P("2. Domain — Google Workspace", "h1"),
        P(
            "The selected domain models a mid-size organisation using Google Workspace. "
            "Employees, managers, administrators, contractors, and auditors interact with "
            "<b>Docs</b>, <b>Gmail</b>, <b>Drive</b>, and <b>Calendar</b>. "
            "The system enforces least-privilege access, separation of duties, and "
            "context-aware restrictions (time-of-day, device type, login location).",
            "body"
        ),
        sp(4),
        P("Resources are classified by sensitivity level:", "body"),
        bullet("<b>public</b> — visible to all authenticated users"),
        bullet("<b>internal</b> — restricted to organisational members by role"),
        bullet("<b>confidential</b> — requires high clearance AND matching department"),
        sp(4),
        P("User attributes tracked: department, clearance level (low/medium/high), employment type, is_auditor.", "body"),
    ]

    # ── 3. RBAC Design ────────────────────────────────────────────────────────
    story += [
        hr(),
        P("3. RBAC Design (RBAC1 — Role Hierarchy)", "h1"),
        P(
            "The system implements <b>RBAC1</b>: roles form an inheritance chain where senior "
            "roles implicitly hold all permissions of junior roles. The chain is stored via "
            "a <code>parent_role</code> column on the <code>roles</code> table and resolved "
            "recursively at evaluation time in <code>rbac.py:get_inherited_roles()</code>.",
            "body"
        ),
        sp(6),
    ]

    hier_data = [
        [Paragraph("<b>Role</b>", S["body"]),
         Paragraph("<b>Inherits From</b>", S["body"]),
         Paragraph("<b>Max Users</b>", S["body"]),
         Paragraph("<b>Key Additions</b>", S["body"])],
        ["administrator", "manager → employee", "5",  "gmail/delete, calendar/delete, system/admin"],
        ["manager",       "employee",           "—",  "docs/delete, docs/share, drive/delete, drive/share"],
        ["employee",      "— (base role)",      "—",  "read+write+comment+send on all resources"],
        ["contractor",    "— (isolated)",        "20", "read+comment on assigned resources only"],
        ["viewer",        "— (isolated)",        "—",  "read+comment on docs; read on others"],
    ]

    hier_style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('INNERGRID',   (0,0), (-1,-1), 0.4, BORDER),
        ('BACKGROUND',  (0,0), (-1, 0), DARK_BG),
        ('TEXTCOLOR',   (0,0), (-1, 0), WHITE),
        ('FONTNAME',    (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 8.5),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',  (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, rlc.HexColor("#f8fafc")]),
        ('BACKGROUND',  (0,1), (-1,1), LIGHT_BLUE),
        ('BACKGROUND',  (0,2), (-1,2), LIGHT_GRN),
        ('BACKGROUND',  (0,3), (-1,3), LIGHT_YEL),
        ('BACKGROUND',  (0,4), (-1,4), LIGHT_RED),
    ])

    story += [
        Table(hier_data, colWidths=[1.0*inch, 1.4*inch, 0.7*inch, 3.1*inch], style=hier_style),
        P("Table 1 — Role hierarchy and key own permissions", "caption"),
        sp(8),
        P("3.1 Full Permission Matrix (own + inherited)", "h2"),
        rbac_matrix_table(),
        P("Table 2 — ✓ = permitted  · = not permitted  (inherited cells included in senior roles)", "caption"),
    ]

    # ── 4. ABAC Policies ─────────────────────────────────────────────────────
    story += [
        hr(),
        P("4. ABAC Policies", "h1"),
        P(
            "Eleven attribute-based policies are evaluated in priority order inside "
            "<code>abac.py:evaluate_abac_policies()</code>. An explicit ABAC <b>deny</b> overrides "
            "any RBAC permit. An explicit ABAC <b>permit</b> (P1) resolves a narrowing conflict "
            "but does not bypass a missing RBAC grant. Context attributes "
            "(<code>hour</code>, <code>device_type</code>, <code>login_location</code>) are "
            "evaluated in policies P8–P11.",
            "body"
        ),
        sp(6),
        abac_policy_table(),
        P("Table 3 — ABAC policies evaluated by the PDP", "caption"),
    ]

    # ── 5. RBAC2 Constraints ──────────────────────────────────────────────────
    story += [
        hr(),
        P("5. RBAC2 Constraints", "h1"),
        P(
            "RBAC2 adds <b>static separation-of-duties</b> constraints and <b>cardinality limits</b>. "
            "Exclusion pairs are stored in the <code>role_exclusions</code> table and checked at "
            "role-assignment time in <code>app.py:assign_role()</code> via "
            "<code>rbac.py:check_role_exclusions()</code> and "
            "<code>check_role_cardinality()</code>. "
            "A user cannot be assigned a role that conflicts with one they already hold, and "
            "capped roles reject new assignments once full.",
            "body"
        ),
        sp(6),
        rbac2_table(),
        P("Table 4 — RBAC2 static SoD exclusions and cardinality limits", "caption"),
    ]

    # ── 6. Demo Scenarios ─────────────────────────────────────────────────────
    story += [
        hr(),
        P("6. Demo Scenarios", "h1"),
        P(
            "The following scenarios are available as one-click Quick Scenarios in the "
            "simulator UI and exercise every policy path:",
            "body"
        ),
        sp(4),
    ]

    demo_data = [
        [Paragraph("<b>Scenario</b>", S["body"]),
         Paragraph("<b>User</b>", S["body"]),
         Paragraph("<b>Action/Resource</b>", S["body"]),
         Paragraph("<b>Expected</b>", S["body"]),
         Paragraph("<b>Policy</b>", S["body"])],
        ["Employee: own doc write",         "carol",  "write / Q1 Report",           "PERMIT", "RBAC1+P1"],
        ["Employee: unowned doc write",      "carol",  "write / Confidential Doc",    "DENY",   "P1"],
        ["Employee: comment on doc",         "carol",  "comment / Q1 Report",         "PERMIT", "RBAC1"],
        ["Manager inherits employee read",   "bob",    "read / Q1 Report",            "PERMIT", "RBAC1"],
        ["Manager: share Drive",             "bob",    "share / Engineering Drive",   "PERMIT", "RBAC1+P4"],
        ["Contractor: assigned read",        "dave",   "read / Q1 Report",            "PERMIT", "P3"],
        ["Contractor: unassigned read",      "dave",   "read / Public Announcement",  "DENY",   "P3"],
        ["Contractor: write blocked",        "dave",   "write / Q1 Report",           "DENY",   "P2"],
        ["Employee: share Drive blocked",    "carol",  "share / Engineering Drive",   "DENY",   "P4"],
        ["Confidential: high clearance",     "bob",    "read / Confidential Doc",     "PERMIT", "P5"],
        ["Confidential: low clearance",      "carol",  "read / Confidential Doc",     "DENY",   "P5"],
        ["Ext. email: send blocked",         "dave",   "send / Org Inbox",            "DENY",   "P6"],
        ["Auditor: share blocked (SoD)",     "frank",  "share / Engineering Drive",   "DENY",   "P7"],
        ["Contractor: off-hours",            "dave",   "read / Q1 Report (hr=22)",    "DENY",   "P8"],
        ["Personal device + confidential",   "bob",    "read / Confidential (dev=personal)", "DENY", "P9"],
        ["Remote: admin blocked",            "alice",  "admin / system (loc=remote)", "DENY",   "P10"],
        ["Remote: conf low clearance",       "carol",  "read / Confidential (remote)","DENY",   "P11"],
        ["RBAC2: SoD exclusion test",        "(admin)", "assign contractor to manager","REJECT", "RBAC2"],
    ]

    demo_style = TableStyle([
        ('BOX',         (0,0), (-1,-1), 1, BORDER),
        ('LINEBELOW',   (0,0), (-1,-2), 0.4, BORDER),
        ('BACKGROUND',  (0,0), (-1, 0), DARK_BG),
        ('TEXTCOLOR',   (0,0), (-1, 0), WHITE),
        ('FONTNAME',    (0,0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 8),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',  (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0),(-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, rlc.HexColor("#f8fafc")]),
    ])

    # Colour PERMIT/DENY cells
    for i, row in enumerate(demo_data[1:], start=1):
        verdict = row[3]
        bg = LIGHT_GRN if verdict == "PERMIT" else LIGHT_RED if verdict == "DENY" else LIGHT_YEL
        demo_style.add('BACKGROUND', (3, i), (3, i), bg)

    story += [
        Table(demo_data,
              colWidths=[1.9*inch, 0.6*inch, 1.9*inch, 0.65*inch, 0.7*inch],
              style=demo_style),
        P("Table 5 — Demo scenarios covering all 11 ABAC policies + RBAC1/RBAC2", "caption"),
    ]

    # ── 7. Conclusion ─────────────────────────────────────────────────────────
    story += [
        hr(),
        P("7. Conclusion", "h1"),
        P(
            "The system delivers a complete, deployable hybrid RBAC+ABAC access control solution "
            "for a cloud productivity domain. Key achievements:",
            "body"
        ),
        bullet("<b>RBAC1 hierarchy</b> — administrator ← manager ← employee inheritance resolved "
               "at query time; only delta permissions stored per role."),
        bullet("<b>RBAC2 constraints</b> — four static SoD exclusion pairs plus cardinality caps "
               "(5 admins, 20 contractors) enforced at role-assignment time."),
        bullet("<b>11 ABAC policies</b> — covering role narrowing, ownership, clearance, department "
               "matching, org email, SoD, time-of-day, device type, and login location."),
        bullet("<b>PAP/PDP/PEP architecture</b> — clean separation of policy administration, "
               "decision logic, and enforcement across Flask endpoints and modules."),
        bullet("<b>Audit logging</b> — every access decision (permit/deny) is logged with user, "
               "resource, action, reason, and timestamp; viewable only by admins (auth enforced)."),
        bullet("<b>Interactive UI</b> — web dashboard with 18 one-click demo scenarios, live "
               "role/hierarchy matrix, RBAC2 constraint viewer, and user registration with role assignment."),
        sp(8),
        P(
            "AI tools (Claude Code) were used for implementation guidance and code generation. "
            "All design decisions, policy logic, and architecture were authored and understood by the team.",
            "body"
        ),
    ]

    doc.build(story)
    print("report.pdf generated.")


if __name__ == "__main__":
    build()

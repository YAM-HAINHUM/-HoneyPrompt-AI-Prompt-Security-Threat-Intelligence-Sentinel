"""
report_generators.py — Professional PDF and Excel generation for HoneyPrompt Sentinel.
Creates high-quality branded PDF security reports and multi-sheet .xlsx workbooks.
"""
from datetime import datetime
import io


# ---------------------------------------------------------------------------
# Formatting Helpers
# ---------------------------------------------------------------------------

def _fmt(v, default="—"):
    if v is None or v == "":
        return default
    return str(v)


def _pct(v):
    if v is None:
        return "—"
    try:
        val = float(v)
        if val <= 1.0:
            return f"{val * 100:.1f}%"
        return f"{val:.1f}%"
    except Exception:
        return str(v)


def _date(ts):
    if not ts or ts == "—" or ts == "None":
        return "—"
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)[:16]


# ---------------------------------------------------------------------------
# PDF Generation (ReportLab)
# ---------------------------------------------------------------------------

def generate_pdf(report_type: str, data: dict, generated_by: str, filters: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    )
    from reportlab.pdfgen import canvas

    class NumberedCanvas(canvas.Canvas):
        """Two-pass canvas to calculate total page count and add standard footer."""
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_footer(num_pages)
                super().showPage()
            super().save()

        def draw_page_footer(self, page_count):
            self.saveState()
            self.setFont("Helvetica", 7)
            self.setFillColor(colors.HexColor("#64748b"))
            # Footer text
            footer_text = f"HoneyPrompt Sentinel V2.4 — Confidential Security Report"
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawString(18 * mm, 12 * mm, footer_text)
            self.drawRightString(210 * mm - 18 * mm, 12 * mm, page_text)
            self.setStrokeColor(colors.HexColor("#334155"))
            self.setLineWidth(0.5)
            self.line(18 * mm, 16 * mm, 210 * mm - 18 * mm, 16 * mm)
            self.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
    )

    styles = getSampleStyleSheet()

    GOLD = colors.HexColor("#F5C518")
    AMBER = colors.HexColor("#D97706")
    RED = colors.HexColor("#EF4444")
    GREEN = colors.HexColor("#10B981")
    DARK = colors.HexColor("#0F172A")
    SLATE = colors.HexColor("#1E293B")
    CARD_BG = colors.HexColor("#141E33")
    GRAY = colors.HexColor("#94A3B8")
    TEXT_LIGHT = colors.HexColor("#F1F5F9")

    title_style = ParagraphStyle(
        "HPTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=18, textColor=GOLD, alignment=0, spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        "HPSubtitle", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9, textColor=GRAY, spaceAfter=2
    )
    h2_style = ParagraphStyle(
        "HPH2", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=11, textColor=GOLD, spaceBefore=12, spaceAfter=6
    )
    conf_style = ParagraphStyle(
        "HPConf", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=7, textColor=RED, spaceAfter=2, alignment=2
    )
    cell_hdr = ParagraphStyle(
        "HPCellHdr", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=7.5, textColor=GOLD, alignment=0
    )
    cell_body = ParagraphStyle(
        "HPCellBody", parent=styles["Normal"],
        fontName="Helvetica", fontSize=7, textColor=TEXT_LIGHT, leading=9
    )
    cell_body_bold = ParagraphStyle(
        "HPCellBodyBold", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=7, textColor=TEXT_LIGHT, leading=9
    )

    def wrap_cells(rows, is_hdr=False):
        style = cell_hdr if is_hdr else cell_body
        out = []
        for r in rows:
            out_row = []
            for c in r:
                if isinstance(c, Paragraph):
                    out_row.append(c)
                else:
                    out_row.append(Paragraph(str(c) if c is not None else "—", style))
            out.append(out_row)
        return out

    def make_table(headers, rows, col_widths=None):
        hdr_row = wrap_cells([headers], is_hdr=True)
        data_rows = wrap_cells(rows if rows else [["No records found"] + [""] * (len(headers) - 1)])
        table_data = hdr_row + data_rows
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SLATE, CARD_BG]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#334155")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    story = []

    # Report Header Block
    type_titles = {
        "security_overview": "Executive Security Overview Report",
        "threat_intelligence": "Threat Intelligence & Attack Analysis Report",
        "user_security": "Enterprise User Security & Risk Report",
        "audit_log": "SOC Security Audit & Compliance Log",
        "incidents": "Security Incident Response & Management Report",
        "chat_activity": "Chat Security & Traffic Activity Report",
        "personal_security": "Personal Security & Threat Assessment Report",
        "security_history": "Personal Security Event History Report",
        "my_chat_activity": "Personal Chat & Session Security Report",
        "security_alerts": "Security Alerts & Intrusion Detection Report",
    }
    disp_title = type_titles.get(report_type, f"Security Report — {report_type.upper().replace('_', ' ')}")

    story.append(Paragraph("TOP SECRET // RESTRICTED SECURITY INTEL", conf_style))
    story.append(Paragraph("🐝 HoneyPrompt Sentinel V2.4", title_style))
    story.append(Paragraph(disp_title, ParagraphStyle("HPSubHeading", parent=h2_style, fontSize=12, textColor=AMBER, spaceBefore=2, spaceAfter=4)))
    story.append(Paragraph(f"Generated by: <b>{generated_by}</b>  |  Timestamp: <b>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</b>", subtitle_style))

    # Applied filters banner
    filter_parts = []
    if data.get("date_from") and data.get("date_to"):
        filter_parts.append(f"Window: {data['date_from']} to {data['date_to']}")
    for k in ("classification", "severity", "threat_type", "action", "status", "user"):
        val = filters.get(k)
        if val and str(val).upper() not in ("ALL", ""):
            filter_parts.append(f"{k.replace('_', ' ').title()}: {val}")

    if filter_parts:
        story.append(Paragraph("Applied Filters: " + "  |  ".join(filter_parts), subtitle_style))

    story.append(HRFlowable(width="100%", thickness=1.2, color=GOLD, spaceBefore=4, spaceAfter=8))

    # ---- REPORT TYPE SPECIFIC CONTENT ----

    if report_type == "security_overview":
        s = data.get("summary", {})
        story.append(Paragraph("Executive Summary & Key Security Metrics", h2_style))
        sum_rows = [
            ["Total Prompts Analyzed", _fmt(s.get("total_prompts")), "Overall Security Score", f"{_fmt(s.get('security_score'))} / 100"],
            ["SAFE Prompts", _fmt(s.get("safe")), "SUSPICIOUS Prompts", _fmt(s.get("suspicious"))],
            ["MALICIOUS Blocked", _fmt(s.get("malicious")), "Prompt Block Rate", _pct(s.get("block_rate"))],
            ["Total User Accounts", _fmt(s.get("total_users")), "Currently Blocked Users", _fmt(s.get("blocked_users"))],
            ["Average Confidence", _pct(s.get("avg_confidence")), "Critical / High Threats", f"{_fmt(s.get('critical'))} / {_fmt(s.get('high'))}"],
        ]
        story.append(make_table(["Security Metric", "Value", "Security Metric", "Value"], sum_rows))

        if data.get("threat_by_type"):
            story.append(Paragraph("Threat Distribution by Category", h2_style))
            t_rows = [[k, str(v)] for k, v in sorted(data["threat_by_type"].items(), key=lambda x: -x[1])]
            story.append(make_table(["Threat Category", "Detection Count"], t_rows))

        if data.get("recent_threats"):
            story.append(Paragraph("Recent Critical & High Threat Detections", h2_style))
            r_rows = [
                [_date(r.get("timestamp")), _fmt(r.get("user")), _fmt(r.get("threat_type")), _fmt(r.get("severity")), _fmt(r.get("action")), _fmt(r.get("prompt_preview", ""))[:32]]
                for r in data["recent_threats"][:15]
            ]
            story.append(make_table(["Timestamp", "User", "Threat Type", "Severity", "Action", "Prompt Preview"], r_rows))

    elif report_type == "threat_intelligence":
        story.append(Paragraph("Threat Intelligence Breakdown", h2_style))
        threats = data.get("threats", [])
        t_rows = [
            [_fmt(r.get("threat_type")), _fmt(r.get("count")), _fmt(r.get("severity")), _pct(r.get("avg_confidence")), _fmt(r.get("target_users_count")), _fmt(r.get("blocked_count"))]
            for r in threats
        ]
        story.append(make_table(["Threat Category", "Incidents", "Top Severity", "Avg Confidence", "Targeted Users", "Blocked"], t_rows))

        if data.get("top_users"):
            story.append(Paragraph("Most Targeted Accounts", h2_style))
            u_rows = [[u, str(c)] for u, c in data["top_users"].items()]
            story.append(make_table(["Username", "Total Attack Attempts"], u_rows))

        if data.get("critical_threats"):
            story.append(Paragraph("Critical Attack Log Samples", h2_style))
            c_rows = [
                [_date(r.get("timestamp")), _fmt(r.get("user")), _fmt(r.get("threat_type")), _fmt(r.get("severity")), _fmt(r.get("prompt_preview", ""))[:35]]
                for r in data["critical_threats"][:15]
            ]
            story.append(make_table(["Time", "User", "Threat Type", "Severity", "Prompt Preview"], c_rows))

    elif report_type == "user_security":
        story.append(Paragraph("Enterprise User Security Profiles", h2_style))
        users = data.get("users", [])
        u_rows = [
            [_fmt(r.get("username")), _fmt(r.get("email")), _fmt(r.get("status")), _fmt(r.get("total_prompts")), _fmt(r.get("malicious")), _fmt(r.get("risk_score")), _fmt(r.get("current_restrictions"))]
            for r in users
        ]
        story.append(make_table(["Username", "Email", "Status", "Prompts", "Malicious", "Risk", "Restrictions"], u_rows))

    elif report_type == "audit_log":
        story.append(Paragraph("SOC Audit Log Entries", h2_style))
        logs = data.get("logs", [])
        a_rows = [
            [_date(r.get("timestamp")), _fmt(r.get("admin")), _fmt(r.get("action")), _fmt(r.get("target")), _fmt(r.get("result")), _fmt(r.get("reason", ""))[:36]]
            for r in logs[:35]
        ]
        story.append(make_table(["Timestamp", "Admin", "Action", "Target", "Result", "Reason"], a_rows))

    elif report_type == "incidents":
        story.append(Paragraph("Security Incidents", h2_style))
        incidents = data.get("incidents", [])
        i_rows = [
            [_fmt(r.get("incident_id")), _date(r.get("created_at")), _fmt(r.get("title", ""))[:28], _fmt(r.get("severity")), _fmt(r.get("status")), _fmt(r.get("assigned_admin"))]
            for r in incidents
        ]
        story.append(make_table(["Incident ID", "Created", "Title", "Severity", "Status", "Assigned To"], i_rows))

    elif report_type == "chat_activity":
        s = data.get("summary", {})
        story.append(Paragraph("Chat & Security Traffic Summary", h2_style))
        c_rows = [
            ["Total Chat Conversations", _fmt(s.get("total_conversations")), "Total Messages Exchanged", _fmt(s.get("total_messages"))],
            ["Threat Detections in Chat", _fmt(s.get("threat_detections")), "Blocked Chat Messages", _fmt(s.get("blocked_messages"))],
            ["Suspicious Chat Messages", _fmt(s.get("suspicious_messages")), "Active Chat Accounts", _fmt(s.get("active_chat_users"))],
        ]
        story.append(make_table(["Traffic Metric", "Count", "Traffic Metric", "Count"], c_rows))

    # --- User Specific Reports ---
    elif report_type == "personal_security":
        s = data.get("summary", {})
        story.append(Paragraph("Your Personal Security Summary", h2_style))
        p_rows = [
            ["Account Username", _fmt(s.get("username")), "Account Status", _fmt(s.get("status"))],
            ["Total Prompts Analyzed", _fmt(s.get("total_prompts")), "Personal Security Score", f"{_fmt(s.get('security_score'))} / 100"],
            ["SAFE Prompts", _fmt(s.get("safe")), "SUSPICIOUS Prompts", _fmt(s.get("suspicious"))],
            ["MALICIOUS Prompts", _fmt(s.get("malicious")), "Blocked Prompts", _fmt(s.get("blocked"))],
            ["Average Confidence", _pct(s.get("avg_confidence")), "Current Restrictions", _fmt(s.get("current_restrictions"))],
        ]
        story.append(make_table(["Metric", "Status", "Metric", "Status"], p_rows))

        if data.get("recent_events"):
            story.append(Paragraph("Recent Account Security Events", h2_style))
            e_rows = [
                [_date(r.get("timestamp")), _fmt(r.get("classification")), _fmt(r.get("threat_type")), _fmt(r.get("severity")), _fmt(r.get("action")), _fmt(r.get("prompt_preview", ""))[:32]]
                for r in data["recent_events"]
            ]
            story.append(make_table(["Timestamp", "Class", "Threat Type", "Severity", "Action", "Prompt Preview"], e_rows))

    elif report_type == "security_history":
        story.append(Paragraph("Security History Log", h2_style))
        history = data.get("history", [])
        h_rows = [
            [_date(r.get("timestamp")), _fmt(r.get("classification")), _fmt(r.get("threat_type")), _fmt(r.get("severity")), _pct(r.get("confidence")), _fmt(r.get("action")), _fmt(r.get("prompt_preview", ""))[:28]]
            for r in history[:40]
        ]
        story.append(make_table(["Timestamp", "Class", "Threat Type", "Severity", "Confidence", "Action", "Prompt Preview"], h_rows))

    elif report_type == "my_chat_activity":
        s = data.get("summary", {})
        story.append(Paragraph("Chat Activity Summary", h2_style))
        m_rows = [
            ["Conversations Saved", _fmt(s.get("total_conversations")), "Total Messages", _fmt(s.get("total_messages"))],
            ["Threat Detections", _fmt(s.get("threat_detections")), "Blocked Messages", _fmt(s.get("blocked_messages"))],
        ]
        story.append(make_table(["Metric", "Count", "Metric", "Count"], m_rows))

        if data.get("conversations"):
            story.append(Paragraph("Saved Conversation Sessions", h2_style))
            cv_rows = [
                [_fmt(c.get("title", ""))[:35], _date(c.get("created_at")), _date(c.get("updated_at"))]
                for c in data["conversations"]
            ]
            story.append(make_table(["Conversation Title", "Created At", "Last Updated"], cv_rows))

    elif report_type == "security_alerts":
        story.append(Paragraph("Your Security Alerts", h2_style))
        alerts = data.get("alerts", [])
        al_rows = [
            [_date(r.get("timestamp")), _fmt(r.get("threat_type")), _fmt(r.get("severity")), _fmt(r.get("classification")), _fmt(r.get("action")), _fmt(r.get("status")), _fmt(r.get("description", ""))[:30]]
            for r in alerts
        ]
        story.append(make_table(["Timestamp", "Threat Type", "Severity", "Class", "Action", "Status", "Details"], al_rows))

    elif report_type == "user_chats":
        s = data.get("summary", {})
        story.append(Paragraph("User-Wise Chat & Telemetry Summary", h2_style))
        uc_rows = [
            ["Target User Account", _fmt(s.get("target_user")), "Total Conversations", _fmt(s.get("total_conversations"))],
            ["Total Messages Analyzed", _fmt(s.get("total_messages")), "SAFE Messages", _fmt(s.get("safe"))],
            ["SUSPICIOUS Detections", _fmt(s.get("suspicious")), "MALICIOUS Detections", _fmt(s.get("malicious"))],
            ["Blocked Messages", _fmt(s.get("blocked")), "Total Prompts", _fmt(s.get("total_prompts"))],
        ]
        story.append(make_table(["Metric", "Value", "Metric", "Value"], uc_rows))

        if data.get("messages"):
            story.append(Paragraph("User Message & Prompt Transcripts", h2_style))
            m_rows = [
                [_date(r.get("timestamp")), _fmt(r.get("user")), _fmt(r.get("classification")), _fmt(r.get("threat_type")), _fmt(r.get("action")), _fmt(r.get("prompt", ""))[:28]]
                for r in data["messages"][:30]
            ]
            story.append(make_table(["Timestamp", "User", "Class", "Threat Type", "Action", "Prompt Preview"], m_rows))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Excel Generation (OpenPyXL)
# ---------------------------------------------------------------------------

def generate_excel(report_type: str, data: dict, generated_by: str, filters: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    wb = Workbook()

    GOLD_COLOR = "F5C518"
    DARK_COLOR = "0F172A"
    SLATE_COLOR = "1E293B"
    WHITE_COLOR = "FFFFFF"
    BORDER_COLOR = "334155"

    hdr_font = Font(name="Calibri", bold=True, color=WHITE_COLOR, size=10)
    hdr_fill = PatternFill("solid", fgColor=DARK_COLOR)
    title_font = Font(name="Calibri", bold=True, color="D97706", size=13)
    meta_font = Font(name="Calibri", italic=True, color="64748b", size=9)

    thin_border_side = Side(style="thin", color=BORDER_COLOR)
    cell_border = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=thin_border_side)

    def write_sheet(ws, title, headers, rows):
        ws.title = title
        ws.sheet_properties.tabColor = GOLD_COLOR

        # Title Block
        ws.append([f"HoneyPrompt Sentinel — {title}"])
        ws.append([f"Generated by: {generated_by}  |  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"])
        if data.get("date_from") and data.get("date_to"):
            ws.append([f"Reporting Period: {data['date_from']} to {data['date_to']}"])
        else:
            ws.append([])
        ws.append([])

        # Table Header
        ws.append(headers)
        hdr_row_idx = 5
        for col_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=hdr_row_idx, column=col_idx)
            cell.font = hdr_font
            cell.fill = hdr_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = cell_border

        # Table Data
        for r_idx, row in enumerate(rows, start=hdr_row_idx + 1):
            ws.append([str(v) if v is not None else "" for v in row])
            for col_idx in range(1, len(headers) + 1):
                cell = ws.cell(row=r_idx, column=col_idx)
                cell.border = cell_border
                cell.alignment = Alignment(vertical="center")

        # Column widths auto-fit
        for col_idx in range(1, len(headers) + 1):
            col_letter = get_column_letter(col_idx)
            max_len = max(
                (len(str(ws.cell(row=r, column=col_idx).value or "")) for r in range(hdr_row_idx, ws.max_row + 1)),
                default=10
            )
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 13), 50)

        ws["A1"].font = title_font
        ws["A2"].font = meta_font

    # --- Summary Sheet ---
    ws_sum = wb.active
    summary_rows = []

    s = data.get("summary", {})
    if s:
        for k, v in s.items():
            summary_rows.append([k.replace("_", " ").title(), _fmt(v)])
    else:
        summary_rows.append(["Report Type", report_type])
        summary_rows.append(["Generated At", datetime.now().isoformat()])
        summary_rows.append(["Record Count", str(data.get("record_count", 0))])

    write_sheet(ws_sum, "Summary", ["Metric", "Value"], summary_rows)

    # --- Type specific sheets ---
    if report_type == "security_overview":
        if data.get("users"):
            ws_u = wb.create_sheet("Users")
            write_sheet(ws_u, "Users",
                ["Username", "Email", "Status", "Total Prompts", "SAFE", "SUSPICIOUS", "MALICIOUS", "Blocked", "Risk Score", "Last Activity"],
                [[r.get("username"), r.get("email"), r.get("status"), r.get("total_prompts"),
                  r.get("safe"), r.get("suspicious"), r.get("malicious"), r.get("blocked"),
                  r.get("risk_score"), _date(r.get("last_activity"))]
                 for r in data["users"]])

        if data.get("threat_by_type"):
            ws_t = wb.create_sheet("Threat Categories")
            write_sheet(ws_t, "Threat Categories", ["Threat Category", "Detection Count"],
                [[k, v] for k, v in data["threat_by_type"].items()])

        if data.get("recent_threats"):
            ws_r = wb.create_sheet("Recent Threats")
            write_sheet(ws_r, "Recent Threats",
                ["Timestamp", "User", "Threat Type", "Severity", "Classification", "Action", "Prompt Preview"],
                [[_date(r.get("timestamp")), r.get("user"), r.get("threat_type"), r.get("severity"), r.get("classification"), r.get("action"), r.get("prompt_preview")]
                 for r in data["recent_threats"]])

    elif report_type == "threat_intelligence":
        ws_t = wb.create_sheet("Threats")
        write_sheet(ws_t, "Threats",
            ["Threat Category", "Incidents", "Top Severity", "Avg Confidence", "Targeted Users", "Blocked Count"],
            [[r.get("threat_type"), r.get("count"), r.get("severity"), _pct(r.get("avg_confidence")), r.get("target_users_count"), r.get("blocked_count")]
             for r in data.get("threats", [])])

        if data.get("top_users"):
            ws_u = wb.create_sheet("Targeted Users")
            write_sheet(ws_u, "Targeted Users", ["Username", "Attack Attempts"],
                [[u, c] for u, c in data["top_users"].items()])

        if data.get("critical_threats"):
            ws_c = wb.create_sheet("Critical Threats")
            write_sheet(ws_c, "Critical Threats",
                ["Timestamp", "User", "Threat Type", "Severity", "Confidence", "Action", "Reason", "Prompt Preview"],
                [[_date(r.get("timestamp")), r.get("user"), r.get("threat_type"), r.get("severity"), _pct(r.get("confidence")), r.get("action"), r.get("reason"), r.get("prompt_preview")]
                 for r in data["critical_threats"]])

    elif report_type == "user_security":
        ws_u = wb.create_sheet("Users")
        write_sheet(ws_u, "Users",
            ["Username", "Email", "Role", "Status", "Total Prompts", "SAFE", "SUSPICIOUS", "MALICIOUS", "Blocked", "Consecutive", "Risk Score", "Restrictions", "Last Activity", "Last Threat"],
            [[r.get("username"), r.get("email"), r.get("role"), r.get("status"), r.get("total_prompts"),
              r.get("safe"), r.get("suspicious"), r.get("malicious"), r.get("blocked"),
              r.get("consecutive_malicious"), r.get("risk_score"), r.get("current_restrictions"),
              _date(r.get("last_activity")), r.get("last_threat_type")]
             for r in data.get("users", [])])

    elif report_type == "audit_log":
        ws_a = wb.create_sheet("Audit Logs")
        write_sheet(ws_a, "Audit Logs",
            ["Timestamp", "Admin", "Action", "Target", "Result", "Reason", "Request ID"],
            [[_date(r.get("timestamp")), r.get("admin"), r.get("action"), r.get("target"), r.get("result"), r.get("reason"), r.get("request_id")]
             for r in data.get("logs", [])])

    elif report_type == "incidents":
        ws_i = wb.create_sheet("Incidents")
        write_sheet(ws_i, "Incidents",
            ["Incident ID", "Created At", "Title", "Severity", "Status", "Assigned Admin", "Actions Taken", "Resolution", "Resolved At"],
            [[r.get("incident_id"), _date(r.get("created_at")), r.get("title"), r.get("severity"), r.get("status"), r.get("assigned_admin"), r.get("actions_taken"), r.get("resolution"), _date(r.get("resolved_at"))]
             for r in data.get("incidents", [])])

    elif report_type == "chat_activity":
        ws_c = wb.create_sheet("Conversations")
        write_sheet(ws_c, "Conversations",
            ["Conversation ID", "User", "Title", "Created At", "Last Updated"],
            [[c.get("conversation_id"), c.get("user"), c.get("title"), _date(c.get("created_at")), _date(c.get("updated_at"))]
             for c in data.get("conversations", [])])

    elif report_type == "personal_security":
        if data.get("recent_events"):
            ws_e = wb.create_sheet("Security Events")
            write_sheet(ws_e, "Security Events",
                ["Timestamp", "Classification", "Threat Type", "Severity", "Action", "Prompt Preview"],
                [[_date(r.get("timestamp")), r.get("classification"), r.get("threat_type"), r.get("severity"), r.get("action"), r.get("prompt_preview")]
                 for r in data["recent_events"]])

    elif report_type == "security_history":
        ws_h = wb.create_sheet("History")
        write_sheet(ws_h, "History",
            ["Timestamp", "Classification", "Threat Type", "Severity", "Confidence", "Action", "Reason", "Prompt Preview"],
            [[_date(r.get("timestamp")), r.get("classification"), r.get("threat_type"), r.get("severity"), _pct(r.get("confidence")), r.get("action"), r.get("reason"), r.get("prompt_preview")]
             for r in data.get("history", [])])

    elif report_type == "my_chat_activity":
        ws_c = wb.create_sheet("Chat Sessions")
        write_sheet(ws_c, "Chat Sessions",
            ["Conversation Title", "Created At", "Last Updated"],
            [[c.get("title"), _date(c.get("created_at")), _date(c.get("updated_at"))]
             for c in data.get("conversations", [])])

    elif report_type == "security_alerts":
        ws_a = wb.create_sheet("Security Alerts")
        write_sheet(ws_a, "Security Alerts",
            ["Timestamp", "Threat Type", "Severity", "Classification", "Action", "Status", "Details"],
            [[_date(r.get("timestamp")), r.get("threat_type"), r.get("severity"), r.get("classification"), r.get("action"), r.get("status"), r.get("description")]
             for r in data.get("alerts", [])])

    elif report_type == "user_chats":
        if data.get("conversations"):
            ws_c = wb.create_sheet("Conversations")
            write_sheet(ws_c, "Conversations",
                ["Conversation ID", "User", "Title", "Created At", "Last Updated"],
                [[c.get("conversation_id"), c.get("user"), c.get("title"), _date(c.get("created_at")), _date(c.get("updated_at"))]
                 for c in data.get("conversations", [])])
        if data.get("messages"):
            ws_m = wb.create_sheet("Message Transcripts")
            write_sheet(ws_m, "Message Transcripts",
                ["Timestamp", "User", "Classification", "Threat Type", "Severity", "Confidence", "Action", "Prompt", "Response"],
                [[_date(m.get("timestamp")), m.get("user"), m.get("classification"), m.get("threat_type"), m.get("severity"), _pct(m.get("confidence")), m.get("action"), m.get("prompt"), m.get("response")]
                 for m in data.get("messages", [])])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()

"""
email_service.py — Email delivery service for HoneyPrompt Sentinel security reports.
Reads SMTP credentials safely from backend environment variables.
"""
import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def send_report_email(
    to_email: str,
    subject: str,
    message: str,
    attachment_bytes: bytes,
    filename: str,
    content_type: str = "application/pdf",
    cc_email: str = None,
) -> bool:
    """
    Sends an email with attached security report bytes using SMTP settings from .env.
    If SMTP credentials are not configured, safely simulates delivery for testing/local environments.
    """
    if not to_email or "@" not in to_email:
        raise ValueError("Invalid recipient email address.")

    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "").strip() or smtp_user or "sentinel-reports@honeyprompt.ai"

    # Build MIME Message
    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_email
    if cc_email and "@" in cc_email:
        msg["Cc"] = cc_email
    msg["Subject"] = subject or f"HoneyPrompt Sentinel Report — {filename}"

    body_text = f"{message.strip() if message else 'Please find attached the requested security report from HoneyPrompt Sentinel.'}\n\n---\nHoneyPrompt Sentinel V2.4 Security & Intrusion Detection System\nConfidentiality Notice: This automated transmission contains sensitive security telemetry."
    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    # Attachment
    maintype, subtype = content_type.split("/", 1) if "/" in content_type else ("application", "octet-stream")
    part = MIMEApplication(attachment_bytes, _subtype=subtype, Name=filename)
    part["Content-Disposition"] = f'attachment; filename="{filename}"'
    msg.attach(part)

    recipients = [to_email]
    if cc_email and "@" in cc_email:
        recipients.append(cc_email)

    # Check if SMTP configuration exists
    if not smtp_host or not smtp_user or not smtp_password:
        logging.info(f"[Email Service] SMTP credentials not set. Simulated email sent to {to_email} with attachment {filename} ({len(attachment_bytes)} bytes)")
        print(f"[Email Service] Simulated dispatch: {filename} ({len(attachment_bytes)} bytes) -> {to_email}")
        return True

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_from, recipients, msg.as_string())
        server.quit()
        logging.info(f"[Email Service] Email sent via SMTP to {to_email}")
        return True
    except Exception as exc:
        logging.error(f"[Email Service Error] Failed to send email: {exc}")
        raise RuntimeError(f"Unable to send email: {exc}")

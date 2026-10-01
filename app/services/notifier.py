import logging
import os
from typing import Dict, Any, Optional, List
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("notifier")

class NotificationService:
    def __init__(self):
        self.email_enabled = os.getenv("NOTIFY_EMAIL_ENABLED", "false").lower() == "true"
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.email_from = os.getenv("NOTIFY_EMAIL_FROM", "security-alert@company.local")
        self.email_to = os.getenv("NOTIFY_EMAIL_TO", "soc@company.local")

        self.webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "")
        self.webhook_type = os.getenv("NOTIFY_WEBHOOK_TYPE", "slack").lower()  # slack, teams, telegram, generic

    async def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "HIGH",
        details: Optional[Dict[str, Any]] = None,
        channels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Sends security alert via Webhook and/or Email."""
        results = {"email": False, "webhook": False, "details": []}
        channels = channels or ["webhook", "email"]

        payload_msg = f"[{severity.upper()}] {title}\n{message}"
        if details:
            payload_msg += f"\n\nDettagli: {details}"

        # Webhook Notification
        if "webhook" in channels and self.webhook_url:
            try:
                success = await self._send_webhook(title, message, severity, details)
                results["webhook"] = success
                if success:
                    results["details"].append("Webhook inviato con successo")
                else:
                    results["details"].append("Errore invio Webhook")
            except Exception as e:
                logger.error(f"Errore invio Webhook: {e}")
                results["details"].append(f"Eccezione Webhook: {str(e)}")

        # Email Notification
        if "email" in channels and self.email_enabled:
            try:
                success = self._send_email(f"[{severity}] Security Alert: {title}", payload_msg)
                results["email"] = success
                if success:
                    results["details"].append("Email inviata con successo")
                else:
                    results["details"].append("Errore invio Email")
            except Exception as e:
                logger.error(f"Errore invio Email: {e}")
                results["details"].append(f"Eccezione Email: {str(e)}")

        return results

    async def _send_webhook(self, title: str, message: str, severity: str, details: Optional[Dict[str, Any]]) -> bool:
        """Sends formatted HTTP webhook payload."""
        if not self.webhook_url:
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            if self.webhook_type == "slack":
                color = "#dc2626" if severity in ["CRITICAL", "HIGH"] else "#f59e0b"
                payload = {
                    "attachments": [
                        {
                            "color": color,
                            "title": f"🚨 {title}",
                            "text": message,
                            "fields": [
                                {"title": "Severità", "value": severity, "short": True},
                                {"title": "Ambito", "value": "Perimetro di Sicurezza", "short": True}
                            ]
                        }
                    ]
                }
            elif self.webhook_type == "teams":
                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "DC2626" if severity in ["CRITICAL", "HIGH"] else "F59E0B",
                    "summary": title,
                    "sections": [{
                        "activityTitle": f"🚨 Security Alert: {title}",
                        "text": message,
                        "facts": [{"name": "Severità", "value": severity}]
                    }]
                }
            elif self.webhook_type == "telegram":
                payload = {
                    "text": f"🚨 *{title}*\nSeverità: `{severity}`\n\n{message}",
                    "parse_mode": "Markdown"
                }
            else:
                # Generic JSON Payload
                payload = {
                    "title": title,
                    "message": message,
                    "severity": severity,
                    "details": details or {}
                }

            res = await client.post(self.webhook_url, json=payload)
            return res.status_code in [200, 201, 202, 204]

    def _send_email(self, subject: str, body: str) -> bool:
        """Sends SMTP email message."""
        try:
            msg = MIMEMultipart()
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            if self.smtp_user and self.smtp_password:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.email_from, [self.email_to], msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Errore spedizione email SMTP: {e}")
            return False

notifier = NotificationService()

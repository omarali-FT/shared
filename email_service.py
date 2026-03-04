# services/notifications/email_service.py
"""
Email notification service for alerting admins about malicious submissions.
"""
import json
import logging
import ssl
from typing import List
from decouple import config
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from django.apps import apps

logger = logging.getLogger(__name__)

# Frontend URL for dashboard links in emails
FRONTEND_URL = config("FRONTEND_URL", default="").strip().rstrip("/")


def _get_dashboard_link(submission) -> str:
    if not FRONTEND_URL:
        return ""
    submission_type = getattr(submission, 'submission_type', 'file')
    job_type = "urlJob" if submission_type == "url" else "fileJob"
    return f"{FRONTEND_URL}/en/dashboard/scanJobs/{job_type}?submission_id={submission.id}"


class InsecureEmailBackend(EmailBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def open(self):
        if self.connection:
            return False
        try:
            self.connection = self.connection_class(self.host, self.port, timeout=self.timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if self.use_tls:
                self.connection.starttls(context=context)
            elif self.use_ssl:
                self.connection = self.connection_class(self.host, self.port, timeout=self.timeout)
                self.connection.sock = context.wrap_socket(self.connection.sock, server_hostname=self.host)
            if self.username and self.password:
                self.connection.login(self.username, self.password)
            return True
        except Exception as e:
            logger.error("InsecureEmailBackend connection failed: %s", e)
            if not self.fail_silently:
                raise
            return False


def get_email_settings():
    try:
        EmailSettings = apps.get_model("alertconfig", "EmailSettings")
        db_settings = EmailSettings.get_settings()
        if db_settings.smtp_host:
            return {
                'enabled': db_settings.enabled,
                'smtp_host': db_settings.smtp_host,
                'smtp_port': db_settings.smtp_port,
                'use_tls': db_settings.use_tls,
                'use_ssl': db_settings.use_ssl,
                'verify_ssl': getattr(db_settings, 'verify_ssl', True),
                'username': db_settings.username,
                'password': db_settings.password,
                'from_email': db_settings.from_email,
                'notify_on_malicious': db_settings.notify_on_malicious,
                'notify_on_high_risk': db_settings.notify_on_high_risk,
                'notify_on_medium_risk': getattr(db_settings, 'notify_on_medium_risk', False),
                'notify_on_low_risk': getattr(db_settings, 'notify_on_low_risk', False),
                'notify_on_clean': getattr(db_settings, 'notify_on_clean', False),
                'notify_on_unknown': getattr(db_settings, 'notify_on_unknown', False),
                'notify_on_ioc_match': db_settings.notify_on_ioc_match,
            }
    except Exception as e:
        logger.debug("Could not load email settings from database: %s", e)

    return {
        'enabled': bool(getattr(settings, 'EMAIL_HOST', None)),
        'smtp_host': getattr(settings, 'EMAIL_HOST', ''),
        'smtp_port': getattr(settings, 'EMAIL_PORT', 587),
        'use_tls': getattr(settings, 'EMAIL_USE_TLS', True),
        'use_ssl': getattr(settings, 'EMAIL_USE_SSL', False),
        'verify_ssl': getattr(settings, 'EMAIL_VERIFY_SSL', True),
        'username': getattr(settings, 'EMAIL_HOST_USER', ''),
        'password': getattr(settings, 'EMAIL_HOST_PASSWORD', ''),
        'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@ncsc.local'),
        'notify_on_malicious': True,
        'notify_on_high_risk': True,
        'notify_on_medium_risk': False,
        'notify_on_low_risk': False,
        'notify_on_clean': False,
        'notify_on_unknown': False,
        'notify_on_ioc_match': True,
    }


def get_email_backend():
    email_settings = get_email_settings()
    if not email_settings['smtp_host']:
        return None
    if not email_settings.get('verify_ssl', True):
        return InsecureEmailBackend(
            host=email_settings['smtp_host'],
            port=email_settings['smtp_port'],
            username=email_settings['username'],
            password=email_settings['password'],
            use_tls=email_settings['use_tls'],
            use_ssl=email_settings['use_ssl'],
            timeout=30,
        )
    return EmailBackend(
        host=email_settings['smtp_host'],
        port=email_settings['smtp_port'],
        username=email_settings['username'],
        password=email_settings['password'],
        use_tls=email_settings['use_tls'],
        use_ssl=email_settings['use_ssl'],
        timeout=30,
    )


def get_admin_emails() -> List[str]:
    try:
        EmailSettings = apps.get_model("alertconfig", "EmailSettings")
        db_settings = EmailSettings.get_settings()
        if db_settings.recipient_emails and db_settings.recipient_emails.strip():
            emails = [e.strip() for e in db_settings.recipient_emails.split(',')]
            valid_emails = [e for e in emails if e]
            logger.debug("Loaded %d admin emails from settings: %s", len(valid_emails), valid_emails)
            return valid_emails
    except Exception as e:
        logger.debug("Could not load recipient emails from database: %s", e)

    User = apps.get_model("users", "User")
    admins = User.objects.filter(is_active=True, is_staff=True).values_list('email', flat=True)
    return [email for email in admins if email]


def _get_status_color(status: str) -> tuple:
    status_lower = status.lower() if status else ""
    colors = {
        'malicious':  ('#dc2626', '#fef2f2', '#991b1b'),
        'high_risk':  ('#ea580c', '#fff7ed', '#c2410c'),
        'medium_risk':('#ca8a04', '#fefce8', '#a16207'),
        'low_risk':   ('#2563eb', '#eff6ff', '#1d4ed8'),
        'clean':      ('#16a34a', '#f0fdf4', '#15803d'),
        'unknown':    ('#6b7280', '#f9fafb', '#4b5563'),
    }
    return colors.get(status_lower, colors['unknown'])


def _build_html_email(context: dict, dashboard_link: str = "") -> str:
    """Build HTML email template - no emojis in subjects, safe f-strings."""
    status = context.get('status', 'Unknown')
    status_color, status_bg, status_border = _get_status_color(status)
    status_display = status.replace('_', ' ').title()

    sd = context.get('sandbox_data', {})
    malware_name = sd.get('malware_name', 'N/A') if sd else 'N/A'
    category = sd.get('category', 'N/A') if sd else 'N/A'
    score = sd.get('score', 'N/A') if sd else 'N/A'

    submission_id = context.get('submission_id', 'N/A')
    submission_type = context.get('submission_type', 'N/A')
    original_filename = context.get('original_filename', 'N/A')
    created_at = context.get('created_at', 'N/A')
    sha256 = context.get('sha256', 'N/A')
    md5 = context.get('md5', 'N/A')
    ip_address = context.get('ip_address', 'N/A')
    submitter = context.get('submitter', {})
    username = submitter.get('username', 'Anonymous') if submitter else 'Anonymous'
    user_type = submitter.get('type', 'N/A') if submitter else 'N/A'

    # Build ministry row safely - outside f-string to avoid brace conflicts
    ministry = context.get('ministry', '')
    if ministry:
        ministry_row = (
            "<tr>"
            "<td style=\"color: #1e40af; font-size: 13px; width: 140px;\">Organization</td>"
            "<td style=\"color: #1e3a8a; font-size: 13px; font-weight: 600;\">" + str(ministry) + "</td>"
            "</tr>"
        )
    else:
        ministry_row = ""

    # Build dashboard button safely - outside f-string
    if dashboard_link:
        dashboard_btn = (
            "<tr>"
            "<td style=\"padding: 20px 40px; text-align: center;\">"
            "<a href=\"" + dashboard_link + "\" target=\"_blank\" "
            "style=\"display: inline-block; background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%); "
            "color: #ffffff; text-decoration: none; padding: 14px 35px; border-radius: 8px; "
            "font-size: 15px; font-weight: 600;\">"
            "View Details in Dashboard"
            "</a>"
            "</td>"
            "</tr>"
        )
    else:
        dashboard_btn = ""

    html = (
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "</head>"
        "<body style=\"margin: 0; padding: 0; font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f3f4f6; padding: 20px 0;\">"
        "<tr><td align=\"center\">"
        "<table width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #ffffff; border-radius: 12px; overflow: hidden;\">"

        # Header
        "<tr><td style=\"background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%); padding: 30px 40px; text-align: center;\">"
        "<h1 style=\"margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;\">NCSC Security Alert</h1>"
        "<p style=\"margin: 10px 0 0 0; color: #94a3b8; font-size: 14px;\">Automated Threat Detection Notification</p>"
        "</td></tr>"

        # Status Badge
        "<tr><td style=\"padding: 30px 40px 20px 40px; text-align: center;\">"
        "<span style=\"display: inline-block; background-color: " + status_bg + "; color: " + status_color + "; "
        "border: 2px solid " + status_border + "; padding: 12px 30px; border-radius: 50px; "
        "font-size: 18px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;\">"
        "[ " + status_display + " ]"
        "</span>"
        "</td></tr>"

        # Submission Details
        "<tr><td style=\"padding: 0 40px;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h2 style=\"margin: 0 0 15px 0; color: #1e293b; font-size: 16px; font-weight: 600; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;\">Submission Details</h2>"
        "<table width=\"100%\" cellpadding=\"8\" cellspacing=\"0\">"
        "<tr><td style=\"color: #64748b; font-size: 13px; width: 140px;\">Submission ID</td><td style=\"color: #1e293b; font-size: 13px; font-weight: 600;\">#" + str(submission_id) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 13px;\">Type</td><td style=\"color: #1e293b; font-size: 13px; font-weight: 600;\">" + str(submission_type).upper() + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 13px;\">File/URL</td><td style=\"color: #1e293b; font-size: 13px; font-weight: 600; word-break: break-all;\">" + str(original_filename) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 13px;\">Submitted At</td><td style=\"color: #1e293b; font-size: 13px; font-weight: 600;\">" + str(created_at) + "</td></tr>"
        "</table>"
        "</td></tr>"
        "</table>"
        "</td></tr>"

        # File Hashes
        "<tr><td style=\"padding: 20px 40px 0 40px;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #fef3c7; border-radius: 8px; border: 1px solid #fcd34d;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h2 style=\"margin: 0 0 15px 0; color: #92400e; font-size: 16px; font-weight: 600; border-bottom: 2px solid #fcd34d; padding-bottom: 10px;\">File Hashes</h2>"
        "<table width=\"100%\" cellpadding=\"8\" cellspacing=\"0\">"
        "<tr><td style=\"color: #92400e; font-size: 12px; width: 60px; font-weight: 600;\">SHA256</td>"
        "<td style=\"color: #78350f; font-size: 11px; font-family: Courier New, monospace; word-break: break-all; background-color: #fffbeb; padding: 8px; border-radius: 4px;\">" + str(sha256) + "</td></tr>"
        "<tr><td style=\"color: #92400e; font-size: 12px; font-weight: 600;\">MD5</td>"
        "<td style=\"color: #78350f; font-size: 11px; font-family: Courier New, monospace; background-color: #fffbeb; padding: 8px; border-radius: 4px;\">" + str(md5) + "</td></tr>"
        "</table>"
        "</td></tr>"
        "</table>"
        "</td></tr>"

        # Sandbox Analysis
        "<tr><td style=\"padding: 20px 40px 0 40px;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #fef2f2; border-radius: 8px; border: 1px solid #fecaca;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h2 style=\"margin: 0 0 15px 0; color: #991b1b; font-size: 16px; font-weight: 600; border-bottom: 2px solid #fecaca; padding-bottom: 10px;\">Sandbox Analysis</h2>"
        "<table width=\"100%\" cellpadding=\"8\" cellspacing=\"0\">"
        "<tr><td style=\"color: #991b1b; font-size: 13px; width: 140px;\">Malware Name</td><td style=\"color: #7f1d1d; font-size: 13px; font-weight: 700;\">" + str(malware_name) + "</td></tr>"
        "<tr><td style=\"color: #991b1b; font-size: 13px;\">Category</td><td style=\"color: #7f1d1d; font-size: 13px; font-weight: 600;\">" + str(category) + "</td></tr>"
        "<tr><td style=\"color: #991b1b; font-size: 13px;\">Risk Score</td><td style=\"color: #7f1d1d; font-size: 13px; font-weight: 600;\">" + str(score) + "</td></tr>"
        "</table>"
        "</td></tr>"
        "</table>"
        "</td></tr>"

        # Submitter Info
        "<tr><td style=\"padding: 20px 40px 0 40px;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #eff6ff; border-radius: 8px; border: 1px solid #bfdbfe;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h2 style=\"margin: 0 0 15px 0; color: #1e40af; font-size: 16px; font-weight: 600; border-bottom: 2px solid #bfdbfe; padding-bottom: 10px;\">Submitter Information</h2>"
        "<table width=\"100%\" cellpadding=\"8\" cellspacing=\"0\">"
        "<tr><td style=\"color: #1e40af; font-size: 13px; width: 140px;\">Username</td><td style=\"color: #1e3a8a; font-size: 13px; font-weight: 600;\">" + str(username) + "</td></tr>"
        "<tr><td style=\"color: #1e40af; font-size: 13px;\">User Type</td><td style=\"color: #1e3a8a; font-size: 13px; font-weight: 600;\">" + str(user_type) + "</td></tr>"
        "<tr><td style=\"color: #1e40af; font-size: 13px;\">IP Address</td><td style=\"color: #1e3a8a; font-size: 13px; font-weight: 600;\">" + str(ip_address) + "</td></tr>"
        + ministry_row +
        "</table>"
        "</td></tr>"
        "</table>"
        "</td></tr>"

        + dashboard_btn +

        # Footer
        "<tr><td style=\"padding: 30px 40px; text-align: center;\">"
        "<p style=\"margin: 0 0 15px 0; color: #64748b; font-size: 13px;\">JSON analysis data is attached to this email.</p>"
        "<p style=\"margin: 0; color: #94a3b8; font-size: 12px;\">This is an automated alert from NCSC Sandbox Portal.</p>"
        "</td></tr>"

        # Bottom Bar
        "<tr><td style=\"background-color: #1e293b; padding: 20px 40px; text-align: center;\">"
        "<p style=\"margin: 0; color: #94a3b8; font-size: 11px;\">National Cyber Security Center | Sandbox Portal</p>"
        "</td></tr>"

        "</table>"
        "</td></tr>"
        "</table>"
        "</body>"
        "</html>"
    )
    return html


def send_malicious_alert(submission, sandbox_data: dict = None) -> bool:
    try:
        email_settings = get_email_settings()

        if not email_settings['enabled']:
            logger.debug("Email notifications are disabled")
            return False

        try:
            from services.notifications.alert_rule_service import should_send_email
            if not should_send_email(submission.status):
                logger.debug("Email not enabled for status: %s", submission.status)
                return False
        except ImportError:
            status_lower = submission.status.lower() if submission.status else ""
            if status_lower == 'malicious' and not email_settings.get('notify_on_malicious', True):
                return False
            if status_lower == 'high_risk' and not email_settings.get('notify_on_high_risk', True):
                return False

        admin_emails = get_admin_emails()
        if not admin_emails:
            logger.warning("No admin emails configured for malicious file alerts")
            return False

        if not email_settings['smtp_host']:
            logger.warning("Email settings not configured. Skipping malicious alert.")
            return False

        context = {
            'submission_id': submission.id,
            'submission_type': submission.submission_type,
            'status': submission.status,
            'sha256': submission.sha256,
            'md5': getattr(submission, 'md5', None),
            'original_filename': submission.original_filename,
            'ip_address': submission.ip_address,
            'created_at': str(submission.created_at),
            'sandbox_sid': submission.sandbox_sid,
        }

        if submission.portal_user:
            context['submitter'] = {
                'type': 'Portal User',
                'username': submission.portal_user.username,
                'display_name': getattr(submission.portal_user, 'display_name', None),
            }
        elif submission.user:
            context['submitter'] = {
                'type': 'Admin User',
                'username': submission.user.username,
                'email': submission.user.email,
            }
        else:
            context['submitter'] = {'type': 'Anonymous'}

        if submission.ministry:
            context['ministry'] = submission.ministry.name

        if sandbox_data:
            context['sandbox_data'] = sandbox_data
        elif submission.raw_result:
            try:
                result = submission.raw_result.get('result', {})
                data = result.get('data', [])
                if isinstance(data, list) and data:
                    context['sandbox_data'] = data[0]
                elif isinstance(data, dict):
                    context['sandbox_data'] = data
            except Exception:
                pass

        risk_level = submission.status.replace('_', ' ').title()
        # NO emojis in subject - causes SMTP errors on some servers
        subject = "[NCSC ALERT] %s Submission Detected - #%s" % (risk_level, submission.id)

        dashboard_link = _get_dashboard_link(submission)
        html_content = _build_html_email(context, dashboard_link)

        org_line = ("Organization: " + context['ministry'] + "\n") if context.get('ministry') else ""
        dash_line = ("View in Dashboard: " + dashboard_link + "\n") if dashboard_link else ""

        text_content = (
            "NCSC SECURITY ALERT - " + risk_level.upper() + "\n"
            + "=" * 50 + "\n\n"
            "Submission ID: #" + str(context['submission_id']) + "\n"
            "Type: " + str(context['submission_type']) + "\n"
            "Status: " + str(context['status']) + "\n\n"
            "File/URL: " + str(context['original_filename']) + "\n"
            "SHA256: " + str(context['sha256']) + "\n"
            "MD5: " + str(context.get('md5', 'N/A')) + "\n\n"
            "Submitted by: " + str(context['submitter'].get('username', 'Anonymous')) + " (" + str(context['submitter']['type']) + ")\n"
            "IP Address: " + str(context['ip_address']) + "\n"
            "Submitted at: " + str(context['created_at']) + "\n"
            + org_line + dash_line +
            "\n" + "=" * 50 + "\n"
            "JSON analysis data is attached to this email.\n"
        )

        json_data = {
            'submission_id': submission.id,
            'submission_type': submission.submission_type,
            'status': submission.status,
            'sha256': submission.sha256,
            'md5': getattr(submission, 'md5', None),
            'original_filename': submission.original_filename,
            'ip_address': submission.ip_address,
            'created_at': str(submission.created_at),
            'submitter': context['submitter'],
            'ministry': context.get('ministry'),
            'sandbox_data': context.get('sandbox_data'),
        }
        attachments = [(
            "analysis_%s_%s.json" % (submission.id, submission.sha256[:8]),
            json.dumps(json_data, indent=2, default=str),
            "application/json"
        )]

        backend = get_email_backend()
        if not backend:
            logger.error("Could not create email backend")
            return False

        sent_count = 0
        failed_emails = []

        try:
            with backend:
                for admin_email in admin_emails:
                    try:
                        email = EmailMultiAlternatives(
                            subject=subject,
                            body=text_content,
                            from_email=email_settings['from_email'],
                            to=[admin_email],
                            connection=backend,
                        )
                        email.attach_alternative(html_content, "text/html")
                        for filename, content, mimetype in attachments:
                            email.attach(filename, content, mimetype)
                        email.send(fail_silently=False)
                        sent_count += 1
                        logger.debug("Email sent to %s for submission #%s", admin_email, submission.id)
                    except Exception as e:
                        failed_emails.append(admin_email)
                        logger.warning("Failed to send email to %s: %s", admin_email, e)
        except Exception as e:
            logger.error("Email backend connection error: %s", e)
            return False

        if sent_count > 0:
            logger.info("Malicious alert sent for submission #%s to %d/%d admins", submission.id, sent_count, len(admin_emails))
            if failed_emails:
                logger.warning("Failed to send to: %s", ', '.join(failed_emails))
            return True
        else:
            logger.error("Failed to send malicious alert for submission #%s to any admin", submission.id)
            return False

    except Exception as e:
        logger.error("Failed to send malicious alert for submission #%s: %s", submission.id, e)
        return False


def _build_ioc_match_html(submission, matches: List[dict], dashboard_link: str = "") -> str:
    """Build HTML email for IOC match alert."""
    matches_html = ""
    for match in matches:
        severity = match.get('severity', 'medium').lower()
        severity_colors = {
            'critical': ('#dc2626', '#fef2f2'),
            'high':     ('#ea580c', '#fff7ed'),
            'medium':   ('#ca8a04', '#fefce8'),
            'low':      ('#2563eb', '#eff6ff'),
        }
        color, bg = severity_colors.get(severity, severity_colors['medium'])
        matched_text = str(match.get('matched_text', 'N/A'))[:150]
        rule_name = str(match.get('rule_name', 'Unknown'))
        cat = str(match.get('category', 'N/A'))
        matches_html += (
            "<tr><td style=\"padding: 15px; border-bottom: 1px solid #e2e8f0;\">"
            "<div style=\"font-weight: 600; color: #1e293b; margin-bottom: 5px;\">" + rule_name + "</div>"
            "<div style=\"margin-bottom: 8px;\">"
            "<span style=\"background-color: " + bg + "; color: " + color + "; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;\">" + severity.upper() + "</span>"
            "&nbsp;&nbsp;<span style=\"color: #64748b; font-size: 12px;\">" + cat + "</span>"
            "</div>"
            "<div style=\"background-color: #f1f5f9; padding: 8px 12px; border-radius: 6px; font-family: monospace; font-size: 11px; color: #475569; word-break: break-all;\">" + matched_text + "...</div>"
            "</td></tr>"
        )

    if dashboard_link:
        dashboard_btn = (
            "<tr><td style=\"padding: 20px 40px; text-align: center;\">"
            "<a href=\"" + dashboard_link + "\" style=\"display: inline-block; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); "
            "color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-size: 14px; font-weight: 600;\">View Details</a>"
            "</td></tr>"
        )
    else:
        dashboard_btn = ""

    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>"
        "<body style=\"margin: 0; padding: 0; font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f3f4f6; padding: 20px 0;\">"
        "<tr><td align=\"center\">"
        "<table width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #ffffff; border-radius: 12px; overflow: hidden;\">"

        "<tr><td style=\"background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); padding: 30px 40px; text-align: center;\">"
        "<h1 style=\"margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;\">IOC Rule Match Alert</h1>"
        "<p style=\"margin: 10px 0 0 0; color: #fef3c7; font-size: 14px;\">Suspicious Patterns Detected</p>"
        "</td></tr>"

        "<tr><td style=\"padding: 25px 40px;\">"
        "<div style=\"background-color: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 15px 20px;\">"
        "<p style=\"margin: 0; color: #92400e; font-size: 14px;\">"
        "<strong>Status Changed:</strong> A submission marked as Clean by the sandbox has been changed to Unknown because IOC rules matched suspicious patterns."
        "</p></div></td></tr>"

        "<tr><td style=\"padding: 0 40px;\">"
        "<table width=\"100%\" style=\"background-color: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h3 style=\"margin: 0 0 15px 0; color: #1e293b; font-size: 14px;\">Submission Details</h3>"
        "<table width=\"100%\" cellpadding=\"6\">"
        "<tr><td style=\"color: #64748b; font-size: 12px; width: 120px;\">ID</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600;\">#" + str(submission.id) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">Type</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600;\">" + str(submission.submission_type).upper() + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">File/URL</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600; word-break: break-all;\">" + str(submission.original_filename) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">SHA256</td><td style=\"color: #1e293b; font-size: 10px; font-family: monospace; word-break: break-all;\">" + str(submission.sha256) + "</td></tr>"
        "</table></td></tr></table></td></tr>"

        "<tr><td style=\"padding: 20px 40px;\">"
        "<h3 style=\"margin: 0 0 15px 0; color: #1e293b; font-size: 14px;\">Matched IOC Rules (" + str(len(matches)) + ")</h3>"
        "<table width=\"100%\" style=\"background-color: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0;\">"
        + matches_html +
        "</table></td></tr>"

        + dashboard_btn +

        "<tr><td style=\"padding: 20px 40px; text-align: center; border-top: 1px solid #e2e8f0;\">"
        "<p style=\"margin: 0; color: #64748b; font-size: 12px;\">JSON analysis data is attached. Please review this submission in the NCSC Portal.</p>"
        "</td></tr>"

        "<tr><td style=\"background-color: #1e293b; padding: 15px; text-align: center;\">"
        "<p style=\"margin: 0; color: #94a3b8; font-size: 11px;\">National Cyber Security Center | Sandbox Portal</p>"
        "</td></tr>"

        "</table></td></tr></table></body></html>"
    )


def _build_behavior_html(submission, indicators: List[dict], dashboard_link: str = "") -> str:
    """Build HTML email for behavior indicator alert."""
    indicators_html = ""
    for ind in indicators:
        rating = ind.get('rating', 'suspicious').lower()
        rating_colors = {
            'malicious':     ('#dc2626', '#fef2f2'),
            'suspicious':    ('#ea580c', '#fff7ed'),
            'informational': ('#2563eb', '#eff6ff'),
        }
        color, bg = rating_colors.get(rating, rating_colors['suspicious'])
        indicator_text = str(ind.get('indicator', 'N/A'))
        ind_type = str(ind.get('type', 'N/A'))
        indicators_html += (
            "<tr><td style=\"padding: 12px 15px; border-bottom: 1px solid #e2e8f0;\">"
            "<div style=\"font-weight: 600; color: #1e293b; font-size: 13px; margin-bottom: 5px;\">" + indicator_text + "</div>"
            "<div>"
            "<span style=\"background-color: " + bg + "; color: " + color + "; padding: 2px 10px; border-radius: 12px; font-size: 10px; font-weight: 600;\">" + rating.upper() + "</span>"
            "&nbsp;&nbsp;<span style=\"color: #64748b; font-size: 11px;\">" + ind_type + "</span>"
            "</div>"
            "</td></tr>"
        )

    submitter = "Anonymous"
    if submission.portal_user:
        submitter = str(submission.portal_user.username) + " (Portal User)"
    elif submission.user:
        submitter = str(submission.user.username) + " (Admin)"

    ministry = submission.ministry.name if submission.ministry else "N/A"

    if dashboard_link:
        dashboard_btn = (
            "<tr><td style=\"padding: 20px 40px; text-align: center;\">"
            "<a href=\"" + dashboard_link + "\" target=\"_blank\" "
            "style=\"display: inline-block; background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%); "
            "color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-size: 14px; font-weight: 600;\">View Details</a>"
            "</td></tr>"
        )
    else:
        dashboard_btn = ""

    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>"
        "<body style=\"margin: 0; padding: 0; font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;\">"
        "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #f3f4f6; padding: 20px 0;\">"
        "<tr><td align=\"center\">"
        "<table width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color: #ffffff; border-radius: 12px; overflow: hidden;\">"

        "<tr><td style=\"background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%); padding: 30px 40px; text-align: center;\">"
        "<h1 style=\"margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;\">Behavior Indicator Alert</h1>"
        "<p style=\"margin: 10px 0 0 0; color: #ddd6fe; font-size: 14px;\">Suspicious Runtime Behavior Detected</p>"
        "</td></tr>"

        "<tr><td style=\"padding: 25px 40px;\">"
        "<div style=\"background-color: #f5f3ff; border: 1px solid #c4b5fd; border-radius: 8px; padding: 15px 20px;\">"
        "<p style=\"margin: 0; color: #5b21b6; font-size: 14px;\">"
        "<strong>Status Changed:</strong> A submission marked as Clean by the sandbox has been changed to Unknown due to suspicious behavior indicators."
        "</p></div></td></tr>"

        "<tr><td style=\"padding: 0 40px;\">"
        "<table width=\"100%\" style=\"background-color: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;\">"
        "<tr><td style=\"padding: 20px;\">"
        "<h3 style=\"margin: 0 0 15px 0; color: #1e293b; font-size: 14px;\">Submission Details</h3>"
        "<table width=\"100%\" cellpadding=\"6\">"
        "<tr><td style=\"color: #64748b; font-size: 12px; width: 120px;\">ID</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600;\">#" + str(submission.id) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">File/URL</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600; word-break: break-all;\">" + str(submission.original_filename) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">SHA256</td><td style=\"color: #1e293b; font-size: 10px; font-family: monospace; word-break: break-all;\">" + str(submission.sha256) + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">Submitted By</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600;\">" + submitter + "</td></tr>"
        "<tr><td style=\"color: #64748b; font-size: 12px;\">Organization</td><td style=\"color: #1e293b; font-size: 12px; font-weight: 600;\">" + str(ministry) + "</td></tr>"
        "</table></td></tr></table></td></tr>"

        "<tr><td style=\"padding: 20px 40px;\">"
        "<h3 style=\"margin: 0 0 15px 0; color: #1e293b; font-size: 14px;\">Suspicious Behaviors (" + str(len(indicators)) + ")</h3>"
        "<table width=\"100%\" style=\"background-color: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0;\">"
        + indicators_html +
        "</table></td></tr>"

        + dashboard_btn +

        "<tr><td style=\"padding: 20px 40px; text-align: center; border-top: 1px solid #e2e8f0;\">"
        "<p style=\"margin: 0; color: #64748b; font-size: 12px;\">JSON analysis data is attached.</p>"
        "</td></tr>"

        "<tr><td style=\"background-color: #1e293b; padding: 15px; text-align: center;\">"
        "<p style=\"margin: 0; color: #94a3b8; font-size: 11px;\">National Cyber Security Center | Sandbox Portal</p>"
        "</td></tr>"

        "</table></td></tr></table></body></html>"
    )


def send_ioc_match_alert(submission, matches: List[dict]) -> bool:
    try:
        email_settings = get_email_settings()

        if not email_settings['enabled']:
            logger.debug("Email notifications are disabled")
            return False

        if not email_settings.get('notify_on_ioc_match', True):
            logger.debug("IOC match notifications are disabled")
            return False

        admin_emails = get_admin_emails()
        if not admin_emails:
            logger.warning("No admin emails configured for IOC match alerts")
            return False

        if not email_settings['smtp_host']:
            logger.warning("Email settings not configured. Skipping IOC match alert.")
            return False

        # NO emojis in subject
        subject = "[NCSC WARNING] IOC Rules Matched - Submission #%s" % submission.id
        dashboard_link = _get_dashboard_link(submission)
        html_content = _build_ioc_match_html(submission, matches, dashboard_link)

        rules_list = "\n".join(["- %s (%s)" % (m.get('rule_name', 'Unknown'), m.get('severity', 'N/A')) for m in matches])
        dash_line = ("View in Dashboard: " + dashboard_link + "\n") if dashboard_link else ""

        text_content = (
            "IOC RULE MATCH ALERT\n"
            + "=" * 50 + "\n\n"
            "A submission marked Clean has been changed to Unknown\n"
            "because IOC rules matched suspicious patterns.\n\n"
            "Submission ID: #" + str(submission.id) + "\n"
            "Type: " + str(submission.submission_type) + "\n"
            "File/URL: " + str(submission.original_filename) + "\n"
            "SHA256: " + str(submission.sha256) + "\n\n"
            "Matched Rules: " + str(len(matches)) + "\n"
            + rules_list + "\n"
            + dash_line +
            "\n" + "=" * 50 + "\n"
            "JSON analysis data is attached.\n"
        )

        json_data = {
            'submission_id': submission.id,
            'submission_type': submission.submission_type,
            'original_status': 'Clean',
            'new_status': 'Unknown',
            'sha256': submission.sha256,
            'original_filename': submission.original_filename,
            'matched_ioc_rules': matches,
        }
        attachments = [(
            "ioc_match_%s.json" % submission.id,
            json.dumps(json_data, indent=2, default=str),
            "application/json"
        )]

        backend = get_email_backend()
        if not backend:
            logger.error("Could not create email backend")
            return False

        sent_count = 0
        failed_emails = []

        try:
            with backend:
                for admin_email in admin_emails:
                    try:
                        email = EmailMultiAlternatives(
                            subject=subject,
                            body=text_content,
                            from_email=email_settings['from_email'],
                            to=[admin_email],
                            connection=backend,
                        )
                        email.attach_alternative(html_content, "text/html")
                        for filename, content, mimetype in attachments:
                            email.attach(filename, content, mimetype)
                        email.send(fail_silently=False)
                        sent_count += 1
                        logger.debug("IOC alert sent to %s", admin_email)
                    except Exception as e:
                        failed_emails.append(admin_email)
                        logger.warning("Failed to send IOC alert to %s: %s", admin_email, e)
        except Exception as e:
            logger.error("Email backend connection error: %s", e)
            return False

        if sent_count > 0:
            logger.info("IOC match alert sent for submission #%s to %d/%d admins", submission.id, sent_count, len(admin_emails))
            return True
        else:
            logger.error("Failed to send IOC match alert for submission #%s to any admin", submission.id)
            return False

    except Exception as e:
        logger.error("Failed to send IOC match alert for submission #%s: %s", submission.id, e)
        return False


def send_behavior_indicator_alert(submission, indicators: List[dict]) -> bool:
    try:
        email_settings = get_email_settings()

        if not email_settings['enabled']:
            logger.debug("Email notifications are disabled")
            return False

        if not email_settings.get('notify_on_ioc_match', True):
            logger.debug("IOC/behavior match notifications are disabled")
            return False

        admin_emails = get_admin_emails()
        if not admin_emails:
            logger.warning("No admin emails configured for behavior indicator alerts")
            return False

        if not email_settings['smtp_host']:
            logger.warning("Email settings not configured. Skipping behavior indicator alert.")
            return False

        # NO emojis in subject
        subject = "[NCSC WARNING] Suspicious Behavior Detected - Submission #%s" % submission.id
        dashboard_link = _get_dashboard_link(submission)
        html_content = _build_behavior_html(submission, indicators, dashboard_link)

        submitter = "Anonymous"
        if submission.portal_user:
            submitter = str(submission.portal_user.username) + " (Portal User)"
        elif submission.user:
            submitter = str(submission.user.username) + " (Admin)"

        org = submission.ministry.name if submission.ministry else 'N/A'
        behaviors_list = "\n".join(["- %s (%s)" % (i.get('indicator', 'N/A'), i.get('rating', 'N/A')) for i in indicators])
        dash_line = ("View in Dashboard: " + dashboard_link + "\n") if dashboard_link else ""

        text_content = (
            "BEHAVIOR INDICATOR ALERT\n"
            + "=" * 50 + "\n\n"
            "A submission marked Clean has been changed to Unknown\n"
            "because suspicious behavior indicators were detected.\n\n"
            "Submission ID: #" + str(submission.id) + "\n"
            "Type: " + str(submission.submission_type) + "\n"
            "File/URL: " + str(submission.original_filename) + "\n"
            "SHA256: " + str(submission.sha256) + "\n"
            "Submitted by: " + submitter + "\n"
            "Organization: " + str(org) + "\n\n"
            "Suspicious Behaviors: " + str(len(indicators)) + "\n"
            + behaviors_list + "\n"
            + dash_line +
            "\n" + "=" * 50 + "\n"
            "JSON analysis data is attached.\n"
        )

        json_data = {
            'submission_id': submission.id,
            'submission_type': submission.submission_type,
            'original_status': 'Clean',
            'new_status': 'Unknown',
            'sha256': submission.sha256,
            'original_filename': submission.original_filename,
            'behavior_indicators': indicators,
        }
        attachments = [(
            "behavior_%s.json" % submission.id,
            json.dumps(json_data, indent=2, default=str),
            "application/json"
        )]

        backend = get_email_backend()
        if not backend:
            logger.error("Could not create email backend")
            return False

        sent_count = 0
        failed_emails = []

        try:
            with backend:
                for admin_email in admin_emails:
                    try:
                        email = EmailMultiAlternatives(
                            subject=subject,
                            body=text_content,
                            from_email=email_settings['from_email'],
                            to=[admin_email],
                            connection=backend,
                        )
                        email.attach_alternative(html_content, "text/html")
                        for filename, content, mimetype in attachments:
                            email.attach(filename, content, mimetype)
                        email.send(fail_silently=False)
                        sent_count += 1
                        logger.debug("Behavior alert sent to %s", admin_email)
                    except Exception as e:
                        failed_emails.append(admin_email)
                        logger.warning("Failed to send behavior alert to %s: %s", admin_email, e)
        except Exception as e:
            logger.error("Email backend connection error: %s", e)
            return False

        if sent_count > 0:
            logger.info("Behavior indicator alert sent for submission #%s to %d/%d admins", submission.id, sent_count, len(admin_emails))
            return True
        else:
            logger.error("Failed to send behavior indicator alert for submission #%s to any admin", submission.id)
            return False

    except Exception as e:
        logger.error("Failed to send behavior indicator alert for submission #%s: %s", submission.id, e)
        return False


def test_email_delivery(test_emails: List[str] = None) -> dict:
    """
    Test email delivery to each configured admin email individually.

    Usage from Django shell:
        from services.notifications.email_service import test_email_delivery
        result = test_email_delivery()
        result = test_email_delivery(['admin1@example.com'])

    Returns:
        dict with 'success', 'failed', and 'errors' keys
    """
    email_settings = get_email_settings()

    if not email_settings['enabled']:
        return {'error': 'Email notifications are disabled'}

    if not email_settings['smtp_host']:
        return {'error': 'SMTP host not configured'}

    emails_to_test = test_emails or get_admin_emails()

    if not emails_to_test:
        return {'error': 'No emails to test'}

    logger.info("Testing email delivery to: %s", emails_to_test)

    results = {'success': [], 'failed': [], 'errors': {}}

    backend = get_email_backend()
    if not backend:
        return {'error': 'Could not create email backend'}

    try:
        with backend:
            for email_addr in emails_to_test:
                try:
                    email = EmailMessage(
                        subject='[NCSC TEST] Email Delivery Test',
                        body='This is a test email to verify delivery to ' + email_addr + '.\n\nIf you receive this, email notifications are working correctly.',
                        from_email=email_settings['from_email'],
                        to=[email_addr],
                        connection=backend,
                    )
                    email.send(fail_silently=False)
                    results['success'].append(email_addr)
                    logger.info("Test email sent successfully to: %s", email_addr)
                except Exception as e:
                    results['failed'].append(email_addr)
                    results['errors'][email_addr] = str(e)
                    logger.error("Failed to send test email to %s: %s", email_addr, e)
    except Exception as e:
        return {'error': 'Backend connection failed: ' + str(e)}

    logger.info("Test complete: %d success, %d failed", len(results['success']), len(results['failed']))
    return results

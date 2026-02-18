"""
Multi-channel notification system for SentinelShield AI Security Platform
Sends alerts via Slack, email, webhooks, and other channels
"""

import asyncio
import json
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NotificationChannel(str, Enum):
    """Notification channels"""
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"
    CONSOLE = "console"


@dataclass
class AlertMessage:
    """Security alert message"""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    title: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = "SentinelShield"
    incident_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Delivery tracking
    delivered_channels: List[str] = field(default_factory=list)
    failed_channels: List[str] = field(default_factory=list)
    delivery_attempts: int = 0


@dataclass
class NotificationRule:
    """Notification routing rule"""
    rule_id: str
    name: str
    conditions: Dict[str, Any]
    channels: List[NotificationChannel]
    enabled: bool = True
    rate_limit_minutes: int = 5
    last_sent: Optional[datetime] = None


class SlackNotifier:
    """Slack notification handler"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def send_alert(self, alert: AlertMessage) -> bool:
        """Send alert to Slack"""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False
        
        try:
            # Determine color based on severity
            color_map = {
                AlertSeverity.LOW: "good",      # green
                AlertSeverity.MEDIUM: "warning", # yellow
                AlertSeverity.HIGH: "danger",    # red
                AlertSeverity.CRITICAL: "#8B0000"  # dark red
            }
            
            color = color_map.get(alert.severity, "warning")
            
            # Create Slack payload
            payload = {
                "text": f"[{alert.severity}] {alert.title}",
                "attachments": [
                    {
                        "color": color,
                        "title": alert.title,
                        "text": alert.message,
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.severity,
                                "short": True
                            },
                            {
                                "title": "Time",
                                "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                "short": True
                            }
                        ],
                        "footer": "SentinelShield Security",
                        "ts": int(alert.timestamp.timestamp())
                    }
                ]
            }
            
            # Add additional fields if available
            if alert.incident_id:
                payload["attachments"][0]["fields"].append({
                    "title": "Incident ID",
                    "value": alert.incident_id,
                    "short": True
                })
            
            if alert.user_id:
                payload["attachments"][0]["fields"].append({
                    "title": "User ID",
                    "value": alert.user_id,
                    "short": True
                })
            
            # Add details as additional attachment if present
            if alert.details:
                details_text = "\n".join([f"• {k}: {v}" for k, v in alert.details.items()])
                payload["attachments"].append({
                    "color": color,
                    "title": "Details",
                    "text": details_text,
                    "mrkdwn_in": ["text"]
                })
            
            # Send to Slack
            response = await self.client.post(self.webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info(f"Slack alert sent: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    async def send_alert(self, alert: AlertMessage, recipients: List[str]) -> bool:
        """Send alert via email"""
        if not recipients:
            logger.warning("No email recipients configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = f"[SentinelShield {alert.severity}] {alert.title}"
            
            # Create HTML body
            html_body = self._create_html_body(alert)
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {len(recipients)} recipients: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _create_html_body(self, alert: AlertMessage) -> str:
        """Create HTML email body"""
        severity_colors = {
            AlertSeverity.LOW: "#28a745",
            AlertSeverity.MEDIUM: "#ffc107",
            AlertSeverity.HIGH: "#dc3545",
            AlertSeverity.CRITICAL: "#6f0000"
        }
        
        color = severity_colors.get(alert.severity, "#ffc107")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px; }}
                .content {{ margin: 20px 0; }}
                .details {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>SentinelShield Security Alert</h2>
                <p><strong>Severity:</strong> {alert.severity}</p>
                <p><strong>Time:</strong> {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            </div>
            
            <div class="content">
                <h3>{alert.title}</h3>
                <p>{alert.message}</p>
            </div>
            
            <div class="details">
                <h4>Details</h4>
                <ul>
        """
        
        if alert.incident_id:
            html += f"<li><strong>Incident ID:</strong> {alert.incident_id}</li>"
        
        if alert.user_id:
            html += f"<li><strong>User ID:</strong> {alert.user_id}</li>"
        
        if alert.session_id:
            html += f"<li><strong>Session ID:</strong> {alert.session_id}</li>"
        
        for key, value in alert.details.items():
            html += f"<li><strong>{key}:</strong> {value}</li>"
        
        html += f"""
                </ul>
            </div>
            
            <div class="footer">
                <p>This alert was generated by SentinelShield AI Security Platform.</p>
                <p>If you believe this is a false positive, please contact the security team.</p>
            </div>
        </body>
        </html>
        """
        
        return html


class WebhookNotifier:
    """Generic webhook notification handler"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def send_alert(self, alert: AlertMessage, webhook_url: str) -> bool:
        """Send alert via webhook"""
        if not webhook_url:
            logger.warning("Webhook URL not provided")
            return False
        
        try:
            # Create webhook payload
            payload = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity,
                "title": alert.title,
                "message": alert.message,
                "source": alert.source,
                "details": alert.details
            }
            
            if alert.incident_id:
                payload["incident_id"] = alert.incident_id
            
            if alert.user_id:
                payload["user_id"] = alert.user_id
            
            if alert.session_id:
                payload["session_id"] = alert.session_id
            
            # Send webhook
            response = await self.client.post(webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info(f"Webhook alert sent: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


class AlertNotifier:
    """Main alert notification system"""
    
    def __init__(self):
        # Initialize notifiers
        self.slack_notifier = None
        self.email_notifier = None
        self.webhook_notifier = WebhookNotifier()
        
        # Configure notifiers based on settings
        if settings.slack_webhook_url:
            self.slack_notifier = SlackNotifier(settings.slack_webhook_url)
        
        if settings.alert_email:
            # Default SMTP settings - would be configurable in real implementation
            self.email_notifier = EmailNotifier(
                smtp_server="smtp.gmail.com",
                smtp_port=587,
                username=settings.alert_email,
                password="password"  # Would be from secure config
            )
        
        # Notification rules
        self.rules = self._initialize_rules()
        
        # Rate limiting
        self.recent_notifications: Dict[str, List[datetime]] = {}
        
        # Statistics
        self.total_alerts = 0
        self.successful_deliveries = 0
        self.failed_deliveries = 0
        
        logger.info("Alert notifier initialized")
    
    def _initialize_rules(self) -> List[NotificationRule]:
        """Initialize notification routing rules"""
        return [
            # Critical alerts go to all channels
            NotificationRule(
                rule_id="critical_all",
                name="Critical alerts to all channels",
                conditions={"severity": AlertSeverity.CRITICAL},
                channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
                rate_limit_minutes=1
            ),
            
            # High severity alerts to Slack and email
            NotificationRule(
                rule_id="high_standard",
                name="High alerts to Slack and email",
                conditions={"severity": AlertSeverity.HIGH},
                channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
                rate_limit_minutes=5
            ),
            
            # Medium severity alerts to Slack only
            NotificationRule(
                rule_id="medium_slack",
                name="Medium alerts to Slack",
                conditions={"severity": AlertSeverity.MEDIUM},
                channels=[NotificationChannel.SLACK],
                rate_limit_minutes=15
            ),
            
            # Low severity alerts to console only
            NotificationRule(
                rule_id="low_console",
                name="Low alerts to console",
                conditions={"severity": AlertSeverity.LOW},
                channels=[NotificationChannel.CONSOLE],
                rate_limit_minutes=30
            ),
            
            # Agent compromise alerts to all channels
            NotificationRule(
                rule_id="agent_compromise",
                name="Agent compromise alerts",
                conditions={"source": "agent_security", "threat_types": ["agent_compromise"]},
                channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
                rate_limit_minutes=1
            ),
        ]
    
    async def send_alert(self, alert: AlertMessage) -> bool:
        """Send alert through appropriate channels"""
        self.total_alerts += 1
        alert.delivery_attempts += 1
        
        try:
            # Find matching rules
            matching_rules = self._find_matching_rules(alert)
            
            if not matching_rules:
                logger.warning(f"No notification rules matched for alert {alert.alert_id}")
                return False
            
            # Send through each channel
            delivery_success = True
            
            for rule in matching_rules:
                # Check rate limiting
                if not self._is_rate_limited(rule):
                    for channel in rule.channels:
                        success = await self._send_to_channel(alert, channel)
                        if success:
                            alert.delivered_channels.append(channel.value)
                        else:
                            alert.failed_channels.append(channel.value)
                            delivery_success = False
                    
                    rule.last_sent = datetime.now(timezone.utc)
                else:
                    logger.debug(f"Alert {alert.alert_id} rate limited for rule {rule.rule_id}")
            
            if delivery_success:
                self.successful_deliveries += 1
            else:
                self.failed_deliveries += 1
            
            return delivery_success
            
        except Exception as e:
            logger.error(f"Failed to send alert {alert.alert_id}: {e}")
            self.failed_deliveries += 1
            return False
    
    def _find_matching_rules(self, alert: AlertMessage) -> List[NotificationRule]:
        """Find notification rules that match the alert"""
        matching_rules = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check severity condition
            if "severity" in rule.conditions:
                if alert.severity != rule.conditions["severity"]:
                    continue
            
            # Check source condition
            if "source" in rule.conditions:
                if alert.source != rule.conditions["source"]:
                    continue
            
            # Check threat types condition
            if "threat_types" in rule.conditions:
                alert_threats = alert.details.get("threat_types", [])
                if not any(threat in alert_threats for threat in rule.conditions["threat_types"]):
                    continue
            
            matching_rules.append(rule)
        
        return matching_rules
    
    def _is_rate_limited(self, rule: NotificationRule) -> bool:
        """Check if rule is rate limited"""
        if rule.rate_limit_minutes <= 0:
            return False
        
        if rule.rule_id not in self.recent_notifications:
            return False
        
        recent = self.recent_notifications[rule.rule_id]
        if not recent:
            return False
        
        # Check if any notification was sent within the rate limit window
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=rule.rate_limit_minutes)
        return any(notification_time > cutoff_time for notification_time in recent)
    
    async def _send_to_channel(self, alert: AlertMessage, channel: NotificationChannel) -> bool:
        """Send alert to specific channel"""
        try:
            if channel == NotificationChannel.SLACK:
                if self.slack_notifier:
                    return await self.slack_notifier.send_alert(alert)
                else:
                    logger.warning("Slack notifier not configured")
                    return False
            
            elif channel == NotificationChannel.EMAIL:
                if self.email_notifier:
                    recipients = [settings.alert_email]  # Would be configurable
                    return await self.email_notifier.send_alert(alert, recipients)
                else:
                    logger.warning("Email notifier not configured")
                    return False
            
            elif channel == NotificationChannel.WEBHOOK:
                # Use default webhook or configured one
                webhook_url = alert.details.get("webhook_url")
                if not webhook_url:
                    logger.warning("No webhook URL provided")
                    return False
                return await self.webhook_notifier.send_alert(alert, webhook_url)
            
            elif channel == NotificationChannel.CONSOLE:
                self._log_to_console(alert)
                return True
            
            else:
                logger.error(f"Unknown notification channel: {channel}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to channel {channel}: {e}")
            return False
    
    def _log_to_console(self, alert: AlertMessage):
        """Log alert to console"""
        severity_symbols = {
            AlertSeverity.LOW: "🟡",
            AlertSeverity.MEDIUM: "🟠",
            AlertSeverity.HIGH: "🔴",
            AlertSeverity.CRITICAL: "🚨"
        }
        
        symbol = severity_symbols.get(alert.severity, "⚠️")
        
        console_msg = f"{symbol} [{alert.severity}] {alert.title}"
        if alert.message:
            console_msg += f" - {alert.message}"
        
        if alert.incident_id:
            console_msg += f" (Incident: {alert.incident_id})"
        
        logger.warning(console_msg)
        
        # Log details at debug level
        if alert.details:
            logger.debug(f"Alert details: {json.dumps(alert.details, indent=2)}")
    
    async def send_daily_digest(self) -> bool:
        """Send daily security digest"""
        try:
            # Generate digest content
            stats = self.get_notification_statistics()
            
            digest_alert = AlertMessage(
                alert_id=f"daily_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.LOW,
                title="SentinelShield Daily Security Digest",
                message=f"Daily summary: {stats['total_alerts']} alerts processed",
                details=stats,
                source="SentinelShield_digest"
            )
            
            # Send to email and Slack
            success = True
            
            if self.email_notifier:
                email_success = await self.email_notifier.send_alert(
                    digest_alert, 
                    [settings.alert_email]
                )
                success = success and email_success
            
            if self.slack_notifier:
                slack_success = await self.slack_notifier.send_alert(digest_alert)
                success = success and slack_success
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to send daily digest: {e}")
            return False
    
    def get_notification_statistics(self) -> Dict[str, Any]:
        """Get notification statistics"""
        return {
            "total_alerts": self.total_alerts,
            "successful_deliveries": self.successful_deliveries,
            "failed_deliveries": self.failed_deliveries,
            "success_rate": self.successful_deliveries / self.total_alerts if self.total_alerts > 0 else 0,
            "configured_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "channels_configured": {
                "slack": self.slack_notifier is not None,
                "email": self.email_notifier is not None,
                "webhook": True
            }
        }
    
    async def close(self):
        """Close all notifiers"""
        if self.slack_notifier:
            await self.slack_notifier.close()
        
        if self.webhook_notifier:
            await self.webhook_notifier.close()


# Global alert notifier instance
alert_notifier = AlertNotifier()

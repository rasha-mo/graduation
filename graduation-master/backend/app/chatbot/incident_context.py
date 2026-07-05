"""
Virex AI Assistant — Incident Context Collector
"""
import logging

logger = logging.getLogger(__name__)

class IncidentContextCollector:
    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance

    def collect(self, incident_id: str) -> dict | None:
        """
        Retrieves detailed structured information about an incident
        to inform the security assistant.
        """
        if not incident_id:
            return None
            
        try:
            # Check the incident cache or db list
            incidents_dict = getattr(self.dashboard, "incidents", {})
            inc = incidents_dict.get(incident_id)
            if not inc:
                # If not found directly, try querying the database
                # (Support direct lookup if DB layer exposes it)
                db = getattr(self.dashboard, "db", None)
                if db:
                    # Optional DB query depending on system configuration
                    pass
                return None

            # Get event snippet payload sample
            events = getattr(inc, "events", [])
            payload_snippet = "N/A"
            if events:
                payload_snippet = events[0].get("snippet") or events[0].get("payload") or "N/A"

            # Parse severity weight for risk scores
            sev_levels = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
            raw_sev = str(getattr(inc, "severity", "MEDIUM")).upper()
            risk_score = sev_levels.get(raw_sev, 50)

            # Build detailed incident meta
            data = {
                "incident_id": incident_id,
                "incident_code": getattr(inc, "incident_code", f"INC-{incident_id[:8].upper()}"),
                "category": getattr(inc, "category", "Unknown Anomaly"),
                "severity": getattr(inc, "severity", "MEDIUM"),
                "source_ip": getattr(inc, "source_ip", "Unknown"),
                "status": getattr(inc, "status", "Unresolved"),
                "risk_score": risk_score,
                "event_count": len(events),
                "payload_sample": payload_snippet,
                "recommendation": self._get_recommended_action(getattr(inc, "category", ""))
            }
            return data
        except Exception as e:
            logger.error(f"[INCIDENT CONTEXT] Failed to retrieve incident details: {e}", exc_info=True)
            return None

    def _get_recommended_action(self, category: str) -> str:
        cat_lower = category.lower()
        if "sql" in cat_lower:
            return "Block Attacking IP immediately. Review vulnerable database queries and enforce Prepared Statements / parameterized execution."
        if "xss" in cat_lower:
            return "Enable rigid Content-Security-Policy (CSP) headers. Escape outputs and sanitize elements using DOMPurify."
        if "brute" in cat_lower or "limit" in cat_lower:
            return "Enforce strict Rate Limiting / sliding-window triggers. Trigger Captcha or account temporary locking policies."
        if "traversal" in cat_lower:
            return "Normalize target filepath parameters. Enforce secure directory boundaries, and restrict server local filesystem permissions."
        if "ssrf" in cat_lower:
            return "Block outgoing requests targeting internal local private IPs (127.0.0.1, 169.254.169.254 cloud metadata APIs)."
        return "Inspect request details, verify if request matches normal traffic (False Positive check), and block IP if anomalous."

    def format_to_text(self, data: dict, lang: str = "en") -> str:
        if not data:
            return ""
            
        if lang == "ar":
            return f"""
تفاصيل الحادثة الأمنية المحددة:
- معرّف الحادثة (ID): {data.get('incident_id')}
- كود الحادثة: {data.get('incident_code')}
- نوع التهديد (Category): {data.get('category')}
- مستوى الخطورة (Severity): {data.get('severity')}
- مصدر عنوان المهاجم (IP): {data.get('source_ip')}
- حالة الحادثة (Status): {data.get('status')}
- مؤشر المخاطر (Risk Score): {data.get('risk_score')}/100
- عدد المحاولات المرتبطة: {data.get('event_count', 1)}
- عينة من البيلود البرمجي (Payload): {data.get('payload_sample')}
- الإجراء الوقائي الموصى به: {data.get('recommendation')}
"""
        return f"""
Currently Selected Incident Context:
- Incident ID: {data.get('incident_id')}
- Incident Code: {data.get('incident_code')}
- Threat Category: {data.get('category')}
- Severity Level: {data.get('severity')}
- Attacking Source IP: {data.get('source_ip')}
- Status: {data.get('status')}
- Risk Score: {data.get('risk_score')}/100
- Number of attack attempts: {data.get('event_count', 1)}
- Attack Sample Payload: {data.get('payload_sample')}
- Recommended Action: {data.get('recommendation')}
"""

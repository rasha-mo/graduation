"""
Dobby — Smart Enterprise AI Security Assistant for Virex WAF & SIEM
===================================================================
A modular co-pilot delegating decisions to specialised engines:
- IntentEngine (Fuzzy logic classification)
- ConversationMemory (Pronouns and entity context tracking)
- DashboardContextCollector & IncidentContextCollector (Stats and timelines)
- PayloadService (Security analyzer and code reviews)
- GeminiService (Cloud integration model)
- ResponseFormatter (Markdown beauty and styling)
"""
import logging
from app.chatbot.security_reasoner import SecurityReasoner

logger = logging.getLogger(__name__)

class SecurityChatbot:
    class Role:
        ADMIN = "admin"
        USER = "user"
        GUEST = "guest"

    def __init__(self, dashboard):
        logger.info("[DOBBY] Initialising Enterprise Security Assistant wrapper...")
        self.reasoner = SecurityReasoner(dashboard)

    def generate_response(
        self,
        user_query: str,
        incident_id: str = None,
        page_context = None,
        history: list = None,
        role: str = "user",
        username: str = "anonymous",
    ) -> str:
        """
        Main entry point backward compatible with dashboard routes.py.
        Delegates the flow reasoning to SecurityReasoner.
        """
        try:
            return self.reasoner.reason(
                query=user_query,
                incident_id=incident_id,
                history=history,
                role=role,
                username=username
            )
        except Exception as e:
            logger.error(f"[DOBBY] Execution failed: {e}", exc_info=True)
            return (
                "عذراً، حدث خطأ داخلي أثناء معالجة طلبك."
                if any('\u0600' <= char <= '\u06FF' for char in user_query)
                else "An internal error occurred while processing your security inquiry."
            )
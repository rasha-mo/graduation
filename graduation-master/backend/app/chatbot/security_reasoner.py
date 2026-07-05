"""
Virex AI Assistant — Security Reasoning and Orchestration Engine
"""
import logging
from app.chatbot.intent_engine import IntentEngine
from app.chatbot.conversation_memory import ConversationMemory
from app.chatbot.dashboard_context import DashboardContextCollector
from app.chatbot.incident_context import IncidentContextCollector
from app.chatbot.payload_service import PayloadService
from app.chatbot.gemini_service import GeminiService
from app.chatbot.prompt_builder import PromptBuilder
from app.chatbot.response_validator import ResponseValidator
from app.chatbot.response_formatter import ResponseFormatter
from app.services.rag_service import SecurityRAGService

logger = logging.getLogger(__name__)

class SecurityReasoner:
    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance
        self.intent_engine = IntentEngine()
        self.memory = ConversationMemory()
        self.dashboard_collector = DashboardContextCollector(dashboard_instance)
        self.incident_collector = IncidentContextCollector(dashboard_instance)
        self.payload_service = PayloadService()
        self.gemini_service = GeminiService()
        self.prompt_builder = PromptBuilder()
        self.validator = ResponseValidator()
        self.formatter = ResponseFormatter()
        
        # Load local RAG service
        try:
            self.rag_service = SecurityRAGService.get_instance()
        except Exception as e:
            logger.error(f"[REASONER] Failed to load SecurityRAGService: {e}")
            self.rag_service = None

    def reason(
        self,
        query: str,
        incident_id: str = None,
        history: list = None,
        role: str = "user",
        username: str = "anonymous"
    ) -> str:
        """
        Orchestrates the entire enterprise execution flow:
        User query
        → IntentEngine (classify)
        → ConversationMemory (resolve references)
        → PayloadService (heuristic signature inspection)
        → DashboardContextCollector (live stats)
        → IncidentContextCollector (details if incident_id)
        → SecurityRAGService (retrieve knowledge chunks)
        → PromptBuilder (compile prompt context)
        → GeminiService (asks Gemini cloud model)
        → ResponseValidator (validates results)
        → ResponseFormatter (ensures Markdown formatting)
        → Final Response
        """
        # 1. Update memory context
        self.memory.add_message(username, "user", query)
        session = self.memory.get_session(username)
        lang = session["preferred_language"]

        # 2. Resolve pronouns (it -> SQL Injection) using Conversational Memory
        resolved_query = self.memory.resolve_pronoun_reference(username, query)

        # 3. Classify intent using Intent Engine
        classification = self.intent_engine.classify(resolved_query)
        intent = classification["intent"]
        confidence = classification["confidence"]
        
        logger.info(f"[REASONER] Routing flow | User: {username} | Intent: {intent} (Conf: {confidence}) | Resolved Query: '{resolved_query}'")

        # 4. Check for code review patterns or malicious query payloads
        payload_analysis = self.payload_service.inspect(resolved_query)
        payload_text = self.payload_service.format_to_text(payload_analysis, lang) if payload_analysis else ""

        # 5. Extract live dashboard metrics (avoiding hallucinations)
        stats = self.dashboard_collector.collect()
        stats_text = self.dashboard_collector.format_to_text(stats, lang)

        # 6. Extract incident timelines and severity levels
        incident_data = self.incident_collector.collect(incident_id) if incident_id else None
        incident_text = self.incident_collector.format_to_text(incident_data, lang) if incident_data else ""

        # 7. Query local RAG database
        rag_context = ""
        if self.rag_service:
            try:
                rag_context = self.rag_service.retrieve(resolved_query) or ""
            except Exception as e:
                logger.error(f"[REASONER] RAG lookup error: {e}")

        # 8. Compile prompt context using the PromptBuilder
        system_instruction = self.prompt_builder.build_system_prompt(
            stats_text=stats_text,
            incident_text=incident_text,
            rag_context=rag_context,
            payload_text=payload_text
        )

        # 9. Execute Gemini AI model (Primary Brain)
        response_text = None
        if self.gemini_service.is_available():
            chat_history = self.memory.get_history(username)
            raw_response = self.gemini_service.ask(system_instruction, resolved_query, chat_history)
            
            # 10. Validate the response
            is_valid, validated_response = self.validator.validate(raw_response, resolved_query, lang)
            if is_valid:
                response_text = validated_response

        # 10b. Fallback pipeline if Gemini is unavailable or rejected by validator
        if not response_text:
            response_text = self._generate_fallback(intent, resolved_query, lang, stats, incident_data, payload_analysis, rag_context)
            # Re-validate fallback response to ensure clean output
            _, response_text = self.validator.validate(response_text, resolved_query, lang)

        # 11. Format final output using ResponseFormatter
        formatted_response = self.formatter.ensure_markdown_aesthetics(response_text)
        
        # Store chatbot response in conversational memory
        self.memory.add_message(username, "assistant", formatted_response)
        return formatted_response

    def _generate_fallback(
        self,
        intent: str,
        query: str,
        lang: str,
        stats: dict,
        incident_data: dict,
        payload_analysis: dict,
        rag_context: str
    ) -> str:
        """Fallback local generation when cloud model is unreachable."""
        if lang == "ar":
            if intent == "greeting":
                return "مرحباً بك! أنا مساعد الحماية الذكي لمشروع Virex. كيف يمكنني مساعدتك اليوم؟ 🛡️"
            if intent == "identity":
                return "أنا Dobby، مساعد الأمان الذكي المدمج في جدار الحماية Virex WAF. يمكنني تحليل الثغرات وفحص البيلود وعرض إحصائيات السيرفر."
            if intent == "system_status":
                return f"حالة النظام الحالية:\n- إجمالي الطلبات: {stats.get('total_requests')}\n- الطلبات المحظورة: {stats.get('blocked_requests')}\n- عنوان المهاجم الأكثر نشاطاً: {stats.get('top_attacker_ip')}"
            if rag_context:
                return f"**نتائج البحث في قاعدة المعرفة المحلية:**\n\n{rag_context}"
            return "عذراً، لم أستطع العثور على إجابة في قاعدة المعرفة المحلية. يرجى تفعيل مفتاح Gemini API Key للحصول على تحليل ذكي متقدم."
        else:
            if intent == "greeting":
                return "Hello! I am Dobby, your Virex WAF Security Co-pilot. How can I assist you with threat analysis today? 🛡️"
            if intent == "identity":
                return "I am Dobby, the built-in AI Security Assistant for Virex WAF. I specialize in real-time SIEM analytics, payload heuristics, and vulnerability remediation."
            if intent == "system_status":
                return f"System health status:\n- Total requests: {stats.get('total_requests')}\n- WAF Blocked count: {stats.get('blocked_requests')}\n- Top Attacker: {stats.get('top_attacker_ip')}"
            if payload_analysis:
                return f"**Local Security Analyzer alert:**\nThreat category: {payload_analysis['highest_severity']} - {payload_analysis['detections'][0]['attack']}"
            if rag_context:
                return f"**Retrieved local security knowledge details:**\n\n{rag_context}"
            return "I couldn't process this query locally. Please provide a GEMINI_API_KEY in your environment to unlock the advanced cloud co-pilot engine."

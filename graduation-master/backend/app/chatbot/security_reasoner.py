"""
Virex AI Assistant — Security Reasoning and Orchestration Engine
"""
import re
import time
import logging
import random
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

class ResponseCache:
    def __init__(self, ttl_seconds=600):
        self.cache = {}
        self.ttl = ttl_seconds
        
    def cleanup(self):
        """Removes expired entries from the cache."""
        now = time.time()
        expired = [
            k
            for k, v in self.cache.items()
            if now - v["timestamp"] > self.ttl
        ]
        for k in expired:
            del self.cache[k]

    def get(self, query: str, incident_id: str, dashboard_version: str) -> str | None:
        self.cleanup()
        key = f"{query.strip().lower()}:{incident_id}:{dashboard_version}"
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry["timestamp"] < self.ttl:
                return entry["response"]
        return None
        
    def set(self, query: str, incident_id: str, dashboard_version: str, response: str):
        key = f"{query.strip().lower()}:{incident_id}:{dashboard_version}"
        self.cache[key] = {
            "response": response,
            "timestamp": time.time()
        }

class AIRateLimiter:
    def __init__(self, limit=20, period=60):
        from collections import defaultdict
        self.limit = limit
        self.period = period
        self.requests = defaultdict(list)
        
    def check_rate_limit(self, username: str) -> bool:
        now = time.time()
        # clean older than 60s
        self.requests[username] = [t for t in self.requests[username] if now - t < self.period]
        if len(self.requests[username]) >= self.limit:
            return True
        self.requests[username].append(now)
        return False

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
        self.gemini_cache = ResponseCache(ttl_seconds=600)
        self.rate_limiter = AIRateLimiter(limit=20, period=60)
        
        # Load local RAG service
        try:
            self.rag_service = SecurityRAGService.get_instance()
        except Exception as e:
            logger.error(f"[REASONER] Failed to load SecurityRAGService: {e}")
            self.rag_service = None

    def is_security_query(
        self,
        query: str,
        intent: str,
        confidence: float,
        has_keyword: bool,
        has_payload: bool,
        has_incident: bool,
        is_dashboard: bool,
        rag_similarity: float
    ) -> bool:
        """
        Determines if a query belongs to the cybersecurity domain.
        """
        SECURITY_INTENTS = {
            "security_definition",
            "mitigation_advice",
            "payload_analysis",
            "incident_query",
            "system_status",
            "attack_stats"
        }
        CONVERSATIONAL_INTENTS = {
            "greeting",
            "thanks",
            "goodbye",
            "identity",
            "how_are_you"
        }
        # Explicit security intents
        if intent in SECURITY_INTENTS and confidence >= 0.75:
            return True
        # Explicit conversational intents
        if intent in CONVERSATIONAL_INTENTS:
            return False
        # Strong local indicators
        if has_keyword:
            return True
        if has_payload:
            return True
        if has_incident:
            return True
        if is_dashboard:
            return True
        # RAG similarity indicates security knowledge
        if rag_similarity >= 0.45:
            return True
        return False

    def reason(
        self,
        query: str,
        incident_id: str = None,
        history: list = None,
        role: str = "user",
        username: str = "anonymous"
    ) -> str:
        """
        Executes the strict copilot query reasoning and routing pipeline.
        """
        start_time = time.time()
        
        # 1. Normalize Query
        cleaned_query = query.strip()
        
        # 2. Update Conversation Memory (includes 30-min inactivity reset)
        self.memory.add_message(username, "user", cleaned_query)
        session = self.memory.get_session(username)
        lang = session.get("preferred_language", "en")
        
        # Retrieve previous topics for system prompt
        previous_topic = session.get("last_security_topic") or ""
        history_list = list(session["history"])
        previous_question = ""
        user_msgs = [m["content"] for m in history_list if m["role"] == "user"]
        if len(user_msgs) > 1:
            previous_question = user_msgs[-2]
            
        # 3. Resolve Pronouns (if indicators match and previous topic exists)
        resolved_query = self.memory.resolve_pronoun_reference(username, cleaned_query)
        
        # 4. Intent Classification
        classification = self.intent_engine.classify(resolved_query)
        intent = classification["intent"]
        confidence = classification["confidence"]
        
        # Update last intent
        session["last_intent"] = intent
        
        # 5. Route 1: Conversation Intents check
        is_conversational = intent in ["greeting", "thanks", "goodbye", "identity", "how_are_you"] and confidence >= 0.75
        if is_conversational:
            from app.chatbot.responses.greeting import get_greeting_response
            from app.chatbot.responses.identity import get_identity_response
            
            if intent == "identity":
                response_text = get_identity_response(lang)
            else:
                response_text = get_greeting_response(intent, lang)
                
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=False, similarity=0.0, payload_det=False, db_used=False,
                incident_used=False, gemini_used=False, path="Conversation -> Local",
                cache_hit=False, resp_time=time.time()-start_time, reason="Conversational intent match"
            )
            return formatted

        # Check local parameters for is_security_query
        from app.models.rag_knowledge import SECURITY_KEYWORDS
        resolved_lower = resolved_query.lower()
        has_security_keyword = any(
            re.search(rf"\b{re.escape(kw)}\b", resolved_lower)
            for kw in SECURITY_KEYWORDS
        )
        
        payload_analysis = self.payload_service.inspect(resolved_query)
        has_payload = bool(payload_analysis and payload_analysis.get("highest_severity") != "Informational" and len(payload_analysis.get("detections", [])) > 0)
        payload_text = self.payload_service.format_to_text(payload_analysis, lang) if payload_analysis else ""
        if has_payload:
            session["last_payload"] = resolved_query
            session["last_ip"] = "127.0.0.1"

        is_dashboard = intent in ["system_status", "attack_stats"] and confidence >= 0.75
        stats = self.dashboard.stats if hasattr(self.dashboard, "stats") else {}
        if not stats and hasattr(self.dashboard, "get_dashboard_data"):
            stats = self.dashboard.get_dashboard_data().get("stats", {})
            
        has_incident = bool(incident_id)
        incident_data = self.incident_collector.collect(incident_id) if incident_id else None
        incident_text = self.incident_collector.format_to_text(incident_data, lang) if incident_data else ""
        if incident_data:
            session["last_incident_id"] = incident_id
            session["last_ip"] = incident_data.get("attacker_ip")
            session["last_endpoint"] = incident_data.get("request_uri")

        # Query local RAG database
        rag_context = ""
        rag_similarity = 0.0
        # If intent is unknown, only query RAG if security keyword exists.
        if self.rag_service and (intent in ["security_definition", "mitigation_advice", "code_review"] or (intent == "unknown" and has_security_keyword)):
            try:
                rag_context, rag_similarity = self.rag_service.retrieve(resolved_query)
            except Exception as e:
                logger.error(f"[REASONER] RAG retrieval failed: {e}")
                
        # Ground context check: Anything below threshold 0.45 returns No Context Found
        if rag_similarity < 0.45:
            rag_context = ""
            
        # Determine Domain Verification status locally
        is_sec = self.is_security_query(
            query=resolved_query,
            intent=intent,
            confidence=confidence,
            has_keyword=has_security_keyword,
            has_payload=has_payload,
            has_incident=has_incident,
            is_dashboard=is_dashboard,
            rag_similarity=rag_similarity
        )
        
        # If not security related OR intent is explicitly out_of_scope -> Route immediately to Out of Scope
        if not is_sec or intent == "out_of_scope":
            from app.chatbot.responses.ood import get_ood_response
            response_text = get_ood_response(lang)
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=has_payload,
                db_used=is_dashboard, incident_used=has_incident, gemini_used=False,
                path="OutOfScope -> Local", cache_hit=False, resp_time=time.time()-start_time,
                reason="Query classified as Out-of-Domain"
            )
            return formatted

        # Route 2: Dashboard Request -> Return Live SIEM
        if is_dashboard:
            from app.chatbot.responses.status import get_status_response
            response_text = get_status_response(resolved_query, lang, stats)
            
            if self.gemini_service.is_available():
                system_instruction = self.prompt_builder.build_system_prompt(
                    intent=intent, confidence=confidence, conversation_summary="",
                    current_incident="", current_dashboard="v1", current_payload="",
                    rag_context="", user_language=lang, current_user_role=role,
                    current_page="Dashboard", current_live_statistics=str(stats),
                    current_security_topic="SIEM Dashboard Status", previous_topic=previous_topic,
                    previous_question=previous_question
                )
                gemini_resp = self.gemini_service.ask(system_instruction, resolved_query, self.memory.get_history(username))
                if gemini_resp:
                    response_text = gemini_resp
                    
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=has_payload,
                db_used=True, incident_used=has_incident, gemini_used=self.gemini_service.is_available(),
                path="Dashboard -> SIEM", cache_hit=False, resp_time=time.time()-start_time,
                reason="Dashboard Request resolved"
            )
            return formatted

        # Route 3: Incident Request -> Return Incident Context
        if has_incident or (intent == "incident_query" and confidence >= 0.75):
            from app.chatbot.responses.incident import get_incident_response
            response_text = get_incident_response(lang, incident_data)
            
            if self.gemini_service.is_available():
                system_instruction = self.prompt_builder.build_system_prompt(
                    intent=intent, confidence=confidence, conversation_summary="",
                    current_incident=incident_text, current_dashboard="v1", current_payload="",
                    rag_context="", user_language=lang, current_user_role=role,
                    current_page="Incident Analysis", current_live_statistics=str(stats),
                    current_security_topic=f"Incident {incident_id}", previous_topic=previous_topic,
                    previous_question=previous_question
                )
                gemini_resp = self.gemini_service.ask(system_instruction, resolved_query, self.memory.get_history(username))
                if gemini_resp:
                    response_text = gemini_resp
                    
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=has_payload,
                db_used=False, incident_used=True, gemini_used=self.gemini_service.is_available(),
                path="Incident -> Analysis", cache_hit=False, resp_time=time.time()-start_time,
                reason="Incident Request resolved"
            )
            return formatted

        # Route 4: Payload Request -> Return Payload Analyzer Heuristics
        if has_payload:
            from app.chatbot.responses.payload import get_payload_response
            response_text = get_payload_response(lang, payload_analysis)
            
            if self.gemini_service.is_available():
                system_instruction = self.prompt_builder.build_system_prompt(
                    intent=intent, confidence=confidence, conversation_summary="",
                    current_incident="", current_dashboard="v1", current_payload=payload_text,
                    rag_context="", user_language=lang, current_user_role=role,
                    current_page="Payload Analysis", current_live_statistics="",
                    current_security_topic="Payload Analyzer Alert", previous_topic=previous_topic,
                    previous_question=previous_question
                )
                gemini_resp = self.gemini_service.ask(system_instruction, resolved_query, self.memory.get_history(username))
                if gemini_resp:
                    response_text = gemini_resp
                    
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=True,
                db_used=False, incident_used=False, gemini_used=self.gemini_service.is_available(),
                path="Payload -> Analyzer", cache_hit=False, resp_time=time.time()-start_time,
                reason="Payload Request resolved"
            )
            return formatted

        # Route 5: Security Question (RAG Retrieval -> Gemini)
        # Check Response Cache (Key: Normalized Query + Incident ID + Dashboard Version)
        dashboard_version = f"{stats.get('total_requests', 0)}:{stats.get('blocked_requests', 0)}"
        cached_response = self.gemini_cache.get(resolved_query, incident_id or "none", dashboard_version)
        if cached_response:
            formatted = self.formatter.ensure_markdown_aesthetics(cached_response)
            self.memory.add_message(username, "assistant", formatted)
            self._write_debug_log(
                original=query, resolved=resolved_query, intent=intent, confidence=confidence,
                keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=has_payload,
                db_used=False, incident_used=has_incident, gemini_used=False,
                path="Security -> Cache", cache_hit=True, resp_time=time.time()-start_time,
                reason="Gemini response retrieved from Cache"
            )
            return formatted

        # AI Rate Limiting Check
        if self.rate_limiter.check_rate_limit(username):
            if lang == "ar":
                response_text = "لقد تجاوزت الحد الأقصى المسموح به لطلبات الذكاء الاصطناعي (20 طلب في الدقيقة). يرجى المحاولة مرة أخرى لاحقاً."
            else:
                response_text = "You have exceeded the maximum limit of AI requests (20 per minute). Please try again later."
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            return formatted

        # Prevent Hallucination Guardrail:
        # If RAG Context, SIEM stats, Incident context, and Payload findings are ALL empty, return localized standard warning
        has_stats_data = bool(stats)
        grounded_context = any([
            rag_context,
            has_stats_data,
            incident_text,
            payload_text
        ])
        if not grounded_context:
            if lang == "ar":
                response_text = "لا أملك معلومات موثوقة عن هذا الموضوع داخل قاعدة المعرفة الحالية."
            else:
                response_text = "I don't have reliable information about this topic."
            formatted = self.formatter.ensure_markdown_aesthetics(response_text)
            self.memory.add_message(username, "assistant", formatted)
            return formatted

        # Build prompt context
        conversation_summary = ""
        if len(history_list) > 0:
            conversation_summary = "\n".join([f"{m['role']}: {m['content']}" for m in history_list[-4:]])
            
        system_instruction = self.prompt_builder.build_system_prompt(
            intent=intent, confidence=confidence, conversation_summary=conversation_summary,
            current_incident=incident_text, current_dashboard="v1", current_payload=payload_text,
            rag_context=rag_context, user_language=lang, current_user_role=role,
            current_page="Security Advisor", current_live_statistics=str(stats),
            current_security_topic=previous_topic or "General Security Inquiry", previous_topic=previous_topic,
            previous_question=previous_question
        )

        response_text = None
        gemini_used = False
        
        # Execute Gemini cloud primary brain
        if self.gemini_service.is_available():
            raw_response = self.gemini_service.ask(system_instruction, resolved_query, self.memory.get_history(username))
            is_valid, validated_response = self.validator.validate(raw_response, resolved_query, lang)
            if is_valid:
                response_text = validated_response
                gemini_used = True

        # Fallback local generation if Gemini is offline
        if not response_text:
            from app.chatbot.responses.security import get_security_response
            response_text = get_security_response(lang, rag_context)
            _, response_text = self.validator.validate(response_text, resolved_query, lang)

        # Dynamic Reference injection
        response_text = self._inject_references_dynamically(resolved_query, response_text)

        # Store in Cache
        self.gemini_cache.set(resolved_query, incident_id or "none", dashboard_version, response_text)

        formatted = self.formatter.ensure_markdown_aesthetics(response_text)
        self.memory.add_message(username, "assistant", formatted)

        # Update last security topic in session dynamically
        TOPIC_MAP = {
            "sql": ("SQL Injection", "sql_injection"),
            "sqli": ("SQL Injection", "sql_injection"),
            "xss": ("XSS (Cross-Site Scripting)", "xss"),
            "csrf": ("CSRF", "csrf"),
            "ssrf": ("SSRF", "ssrf"),
            "idor": ("IDOR", "idor"),
            "xxe": ("XXE", "xxe"),
            "rce": ("Remote Code Execution", "rce"),
            "brute": ("Brute Force", "brute_force"),
            "rate limit": ("Rate Limiting", "rate_limit"),
            "rate limited": ("Rate Limiting", "rate_limit"),
            "rate limiting": ("Rate Limiting", "rate_limit"),
            "scanner": ("Security Scanners", "scanner"),
            "scanners": ("Security Scanners", "scanner"),
            "scanning": ("Security Scanners", "scanner"),
        }
        for keyword, (topic, vuln) in TOPIC_MAP.items():
            if keyword in resolved_lower:
                session["last_security_topic"] = topic
                session["last_vulnerability"] = vuln
                break

        self._write_debug_log(
            original=query, resolved=resolved_query, intent=intent, confidence=confidence,
            keyword_match=has_security_keyword, similarity=rag_similarity, payload_det=has_payload,
            db_used=False, incident_used=has_incident, gemini_used=gemini_used,
            path="Security -> RAG -> Gemini" if gemini_used else "Security -> RAG -> Local Fallback",
            cache_hit=False, resp_time=time.time()-start_time, reason="Security query answered"
        )
        return formatted

    def _inject_references_dynamically(self, query: str, response: str) -> str:
        """Appends specific reference links dynamically based on query threat keywords."""
        if "References" in response:
            return response
            
        query_lower = query.lower()
        refs = []
        
        if re.search(r"\bsql\b", query_lower):
            refs.append("* [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)")
        if re.search(r"\bxss\b", query_lower) or re.search(r"\bcross[ -]site scripting\b", query_lower):
            refs.append("* [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)")
        if re.search(r"\bssrf\b", query_lower):
            refs.append("* [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)")
        if re.search(r"\bcsrf\b", query_lower) or re.search(r"\bxsrf\b", query_lower):
            refs.append("* [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)")
        if "idor" in query_lower:
            refs.append("* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)")
        if "xxe" in query_lower:
            refs.append("* [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)")
        if "rce" in query_lower or "remote code execution" in query_lower:
            refs.append("* [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)")
        if "jwt" in query_lower:
            refs.append("* [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)")
        if "scanner" in query_lower or "scanning" in query_lower:
            refs.append("* [OWASP Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/)")
        if "rate limit" in query_lower or "rate limiting" in query_lower or "rate limited" in query_lower:
            refs.append("* [OWASP Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_of_Functionality_Cheat_Sheet.html)")
        if any(re.search(rf"\b{re.escape(term)}\b", query_lower) for term in ["siem", "dashboard", "attack", "threat"]):
            refs.append("* [MITRE ATT&CK Framework](https://attack.mitre.org/)")
        if any(re.search(rf"\b{re.escape(term)}\b", query_lower) for term in ["secure coding", "mitigate", "prevent", "fix"]):
            refs.append("* [OWASP Cheat Sheets Series](https://cheatsheetseries.owasp.org/)")
            
        if refs:
            ref_section = "\n\n### References\n" + "\n".join(refs)
            return response + ref_section
            
        return response

    def _write_debug_log(
        self, original: str, resolved: str, intent: str, confidence: float,
        keyword_match: bool, similarity: float, payload_det: bool, db_used: bool,
        incident_used: bool, gemini_used: bool, path: str, cache_hit: bool,
        resp_time: float, reason: str
    ):
        log_msg = f"""
=== [CHATBOT STRUCTURED LOG] ===
Original Query: {original}
Resolved Query: {resolved}
Intent: {intent}
Confidence: {confidence:.2f}
Security Keyword Match: {"Yes" if keyword_match else "No"}
RAG Similarity: {similarity:.2f}
Payload Detection: {"Yes" if payload_det else "No"}
Dashboard Used: {"Yes" if db_used else "No"}
Incident Used: {"Yes" if incident_used else "No"}
Gemini Used: {"Yes" if gemini_used else "No"}
Execution Path: {path}
Cache Hit: {"Yes" if cache_hit else "No"}
Response Time: {resp_time:.3f}s
Reason: {reason}
================================
"""
        logger.info(log_msg)

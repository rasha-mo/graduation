"""
Virex AI Assistant — Conversation Memory Service
"""
import re
import logging
from collections import deque

logger = logging.getLogger(__name__)

class ConversationMemory:
    def __init__(self, max_history=20):
        self.max_history = max_history
        # Store user-specific context: username -> {history: deque, entities: dict, lang: str}
        self.sessions = {}

    def get_session(self, username: str) -> dict:
        if username not in self.sessions:
            self.sessions[username] = {
                "history": deque(maxlen=self.max_history),
                "last_vulnerability": None,
                "last_incident_id": None,
                "last_ip": None,
                "last_payload": None,
                "preferred_language": "en"
            }
        return self.sessions[username]

    def add_message(self, username: str, role: str, content: str):
        session = self.get_session(username)
        session["history"].append({"role": role, "content": content})
        
        # Auto-detect language and update preference
        if role == "user":
            has_arabic = any('\u0600' <= char <= '\u06FF' for char in content)
            session["preferred_language"] = "ar" if has_arabic else "en"
            
            # Extract basic entities on the fly
            self.extract_entities(session, content)

    def extract_entities(self, session: dict, text: str):
        # Extract IP Addresses
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        if ip_match:
            session["last_ip"] = ip_match.group(0)

        # Extract Incident ID keywords
        inc_match = re.search(r"incident[-_ ]?([a-fA-F0-9]+)", text, re.IGNORECASE)
        if inc_match:
            session["last_incident_id"] = inc_match.group(1)

        # Extract vulnerability keywords
        vuln_patterns = {
            "sql_injection": [r"sqli", r"sql", r"injection", r"قواعد البيانات"],
            "xss": [r"xss", r"cross site scripting", r"cross-site scripting", r"سكريبت"],
            "csrf": [r"csrf", r"xsrf", r"forgery", r"تزوير الطلبات"],
            "ssrf": [r"ssrf", r"server side", r"server-side"],
            "brute_force": [r"brute", r"bruteforce", r"guessing", r"تخمين"],
            "path_traversal": [r"path traversal", r"directory traversal", r"مسار", r"\.\./"],
            "command_injection": [r"command", r"os injection", r"shell", r"أوامر"]
        }

        for vuln, patterns in vuln_patterns.items():
            if any(re.search(p, text, re.IGNORECASE) for p in patterns):
                session["last_vulnerability"] = vuln
                break

    def get_history(self, username: str) -> list:
        session = self.get_session(username)
        return list(session["history"])

    def resolve_pronoun_reference(self, username: str, query: str) -> str:
        session = self.get_session(username)
        cleaned = query.lower()

        # Check for English pronoun indicators
        en_pronouns = ["it", "them", "this vulnerability", "that", "how do i fix it", "explain it"]
        # Check for Arabic pronoun indicators
        ar_pronouns = ["دي", "الثغرة دي", "حلها", "دي بتشتغل ازاي", "اشرحها", "مثال عليها"]

        needs_resolve = (
            any(p in cleaned for p in en_pronouns) or
            any(p in cleaned for p in ar_pronouns) or
            len(cleaned.split()) < 4 # Short follow-up query like "explain more" or "give me an example"
        )

        if needs_resolve and session["last_vulnerability"]:
            vuln_names = {
                "sql_injection": "SQL Injection",
                "xss": "XSS (Cross-Site Scripting)",
                "csrf": "CSRF (Cross-Site Request Forgery)",
                "ssrf": "SSRF (Server-Side Request Forgery)",
                "brute_force": "Brute Force",
                "path_traversal": "Path Traversal",
                "command_injection": "Command OS Injection"
            }
            mapped_name = vuln_names.get(session["last_vulnerability"], "")
            if mapped_name:
                if session["preferred_language"] == "ar":
                    resolved = f"{query} (المشار إليها: ثغرة {mapped_name})"
                else:
                    resolved = f"{query} (referring to: {mapped_name})"
                logger.debug(f"[MEMORY] Resolved reference: '{query}' -> '{resolved}'")
                return resolved

        return query

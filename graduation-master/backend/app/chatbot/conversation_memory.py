"""
Virex AI Assistant — Conversation Memory Service
"""
import re
import time
import logging
from collections import deque

logger = logging.getLogger(__name__)

class ConversationMemory:
    def __init__(self, max_history=20):
        self.max_history = max_history
        # Store user-specific context: username -> session dict
        self.sessions = {}

    def _create_empty_session(self) -> dict:
        return {
            "history": deque(maxlen=self.max_history),
            "last_intent": None,
            "last_vulnerability": None,
            "last_incident_id": None,
            "last_payload": None,
            "last_ip": None,
            "last_endpoint": None,
            "last_uploaded_code": None,
            "last_language": "en",
            "last_response": None,
            "last_security_topic": None,
            "preferred_language": "en",
            "last_activity_timestamp": time.time()
        }

    def get_session(self, username: str) -> dict:
        now = time.time()
        if username in self.sessions:
            session = self.sessions[username]
            # Session inactivity check (30 minutes = 1800 seconds)
            if now - session.get("last_activity_timestamp", now) > 1800:
                self.sessions[username] = self._create_empty_session()
                logger.info(f"[MEMORY] Session for user '{username}' expired due to 30 minutes of inactivity.")
        else:
            self.sessions[username] = self._create_empty_session()
        
        self.sessions[username]["last_activity_timestamp"] = now
        return self.sessions[username]

    def add_message(self, username: str, role: str, content: str):
        session = self.get_session(username)
        session["history"].append({"role": role, "content": content})
        session["last_activity_timestamp"] = time.time()
        
        if role == "user":
            cleaned = content.strip().lower()
            cleaned_normalized = re.sub(r"[أإآ]", "ا", cleaned)
            cleaned_normalized = re.sub(r"[?.,!؛؟]", "", cleaned_normalized)
            
            pure_attack_terms = {
                "sql", "sqli", "xss", "csrf", "xsrf", "ssrf", "idor", "xxe", 
                "rce", "lfi", "rfi", "ssti", "brute force", "brute", "rate limit", 
                "rate_limit", "rate limited", "rate limiting", "scanner", "scanners", 
                "scanning", "attacks", "threats", "vulnerabilities"
            }
            
            bug_keywords = [
                "bug", "bugs", "vulnerability", "vulnerabilities", "exploit", "exploits",
                "flaw", "flaws", "weakness", "weaknesses",
                "ثغرة", "ثغرات", "ثغره", "ثغراتها", "نقطة ضعف", "نقاط ضعف"
            ]
            
            has_arabic = any('\u0600' <= char <= '\u06FF' for char in content)
            
            contains_bug_keyword = any(re.search(rf"\b{re.escape(kw)}\b", cleaned_normalized) for kw in bug_keywords)
            
            if cleaned_normalized in pure_attack_terms or contains_bug_keyword:
                session["last_language"] = "both"
            elif has_arabic:
                session["last_language"] = "ar"
            else:
                session["last_language"] = "en"
                
            session["preferred_language"] = session["last_language"]
            self.extract_entities(session, content)
        else:
            session["last_response"] = content

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
            "sql_injection": [r"sqli", r"sql", r"injection", r"قواعد البيانات", r"حقن"],
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
                session["last_security_topic"] = vuln.replace("_", " ").upper()
                break

        # Check for code markers (Uploaded Code)
        has_code_markers = any(m in text for m in [
            "def ", "function", "var ", "const ", "let ", "import ", "require("
        ])
        if has_code_markers:
            session["last_uploaded_code"] = text

    def get_history(self, username: str) -> list:
        session = self.get_session(username)
        return list(session["history"])

    def resolve_pronoun_reference(self, username: str, query: str) -> str:
        session = self.get_session(username)
        cleaned = query.lower()

        # Check for English pronoun indicators
        en_pronouns = ["it", "that", "this vulnerability"]
        # Check for Arabic pronoun indicators
        ar_pronouns = ["اشرحها", "حلها", "علاجها", "مثال عليها"]

        # Only resolve pronouns if query contains explicit pronoun indicators AND previous topic/vulnerability exists
        has_pronoun = any(p in cleaned for p in en_pronouns) or any(p in cleaned for p in ar_pronouns)
        has_previous_topic = bool(session.get("last_security_topic") or session.get("last_vulnerability"))

        if has_pronoun and has_previous_topic:
            vuln_names = {
                "sql_injection": "SQL Injection",
                "xss": "XSS (Cross-Site Scripting)",
                "csrf": "CSRF (Cross-Site Request Forgery)",
                "ssrf": "SSRF (Server-Side Request Forgery)",
                "brute_force": "Brute Force",
                "path_traversal": "Path Traversal",
                "command_injection": "Command OS Injection"
            }
            last_vuln = session.get("last_vulnerability") or "sql_injection"
            mapped_name = vuln_names.get(last_vuln, last_vuln.replace("_", " ").upper())
            if mapped_name:
                if session.get("preferred_language") == "ar":
                    resolved = f"{query} (المشار إليها: ثغرة {mapped_name})"
                else:
                    resolved = f"{query} (referring to: {mapped_name})"
                logger.debug(f"[MEMORY] Resolved reference: '{query}' -> '{resolved}'")
                return resolved

        return query

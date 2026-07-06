"""
Virex AI Assistant — Intent Classification Engine
"""
import re
import difflib
import logging

logger = logging.getLogger(__name__)

INTENT_TRIGGERS = {
    "greeting": [
        "hi", "hello", "hey", "good morning", "good evening", "good afternoon",
        "howdy", "whats up", "sup", "greetings", "yo", "hiya",
        "هاي", "هلو", "مرحبا", "السلام عليكم", "اهلا", "اهلين",
        "صباح الخير", "مساء الخير", "ازيك", "هلا", "يسلمو", "وعليكم السلام"
    ],
    "identity": [
        "who are you", "what are you", "your name", "who is dobby",
        "introduce yourself", "tell me about yourself", "what do you do",
        "are you a bot", "are you ai", "are you human", "what is your purpose",
        "how do you work", "what can you do", "your role",
        "مين انت", "انت مين", "اسمك ايه", "عرف نفسك", "اسمك",
        "انت بتعمل ايه", "ايه دورك", "هو انت مين", "انت روبوت"
    ],
    "how_are_you": [
        "how are you", "how are you doing", "are you okay", "you alright",
        "hows it going", "you good", "everything okay",
        "عامل ايه", "ازيك", "اخبارك ايه", "كيفك", "كيف حالك", "انت بخير"
    ],
    "thanks": [
        "thank you", "thanks", "thx", "ty", "appreciate it", "great job",
        "well done", "nice", "awesome", "perfect", "good job",
        "شكرا", "شكراً", "تسلم", "عاش", "كتر خيرك", "يسلمو"
    ],
    "goodbye": [
        "bye", "goodbye", "see you", "farewell", "quit", "exit",
        "سلام", "مع السلامة", "باي", "اشوفك بعدين"
    ],
    "system_status": [
        "system status", "status", "overview", "health", "dashboard",
        "whats happening", "how is the system", "current state",
        "system health", "network status", "security status",
        "show stats", "give me stats", "stats", "summary", "report",
        "الوضع ايه", "ايه الوضع", "احصائيات", "تقرير", "الحالة ايه",
        "حالة النظام", "اخبار النظام", "ايه الاخبار", "احصائيات الهجمات"
    ],
    "attack_stats": [
        "how many", "count", "number of", "statistics", "how many sql",
        "how many xss", "how many brute", "how many scanner", "how many attacks",
        "كم عدد", "عدد هجمات", "كام", "كم هجمة", "كم عدد هجمات"
    ],
    "payload_analysis": [
        "analyze", "payload", "decode", "explain log", "malicious payload",
        "what is this query", "explain request",
        "حلل", "افحص البيلود", "فك التشفير", "تحليل الكود", "حلل هذا الـ payload"
    ],
    "incident_query": [
        "incident", "why was it blocked", "investigate", "tell me about this incident",
        "why block", "incident details", "why did virex block this",
        "الحادثة", "ليه اتحجبت", "سبب الحظر", "تفاصيل الحادثة"
    ],
    "security_definition": [
        "what is", "explain", "how does it work", "tell me about",
        "ما هو", "اشرح", "كيف يعمل", "شرح"
    ],
    "mitigation_advice": [
        "how to fix", "how to prevent", "secure code example", "mitigate", "remediate",
        "prevent", "fix", "secure implementation", "how do i stop",
        "كيفية الاصلاح", "طريقة العلاج", "مثال برمجي امن", "كيف امنع"
    ],
    "out_of_scope": [
        "pizza", "recipe", "cook", "food", "poem", "poetry", "write a poem",
        "calculate", "math", "calculator", "football", "soccer", "player", "best player",
        "weather", "music", "song", "movie", "film", "joke", "tell me a joke",
        "بيتزا", "وصفة", "طبخ", "شعر", "قصيدة", "اكتب شعر", "احسب", "رياضيات", "حساب",
        "كرة قدم", "كورة", "لاعب", "افضل لاعب", "طقس", "موسيقى", "اغنية", "فيلم", "نكتة",
        "لاعب كرة", "من أفضل لاعب", "اكتب قصيدة", "احسب 2+2"
    ]
}

CYBER_SYNONYMS = {
    "sqli": ["sql", "sql injection", "database injection", "union select", "sql query", "حقن استعلامات"],
    "xss": ["cross site scripting", "script injection", "cross-site scripting", "alert(", "onload", "حقن سكريبت"],
    "ssrf": ["server side request forgery", "server-side request forgery", "metadata query", "file://", "تزوير الطلبات من جهة الخادم"],
    "csrf": ["cross site request forgery", "cross-site request forgery", "xsrf", "missing csrf", "تزوير الطلبات عبر المواقع"],
    "brute": ["brute force", "login guessing", "repeated logins", "password attack", "تخمين كلمة المرور"],
    "scanner": ["nikto", "nmap", "gobuster", "sqlmap", "reconnaissance", "scanning", "scanners", "scanner", "فحص الثغرات"],
    "rate_limit": ["rate limiting", "rate limited", "rate limit", "rate-limiting", "rate-limited", "ddos", "dos", "too many requests", "sliding window", "تحديد معدل الطلبات"]
}

SECURITY_TRIGGERS = [
    "sql injection", "sqli", "xss", "cross site scripting", "cross-site scripting",
    "csrf", "xsrf", "ssrf", "rce", "remote code execution", "command injection",
    "directory traversal", "path traversal", "file upload", "idor", "xxe",
    "deserialization", "buffer overflow", "brute force", "rate limit",
    "authentication", "authorization", "jwt", "oauth", "session hijacking",
    "cookie", "cwe", "owasp", "cve", "mitre", "waf", "siem", "payload",
    "malware", "ransomware", "trojan", "worm", "backdoor", "vulnerability",
    "exploit", "penetration testing", "secure coding", "injection",
    "حقن", "ثغرة", "تخطي المصادقة", "اختراق", "تصيد", "برمجية خبيثة", "فدية",
    "تخمين كلمة المرور", "تحديد معدل الطلبات", "مصادقة", "تفويض", "جلسة",
    "lfi", "rfi", "ssti", "ldap injection", "xpath injection",
    "os command injection", "clickjacking", "cors", "csp",
    "http security headers", "security headers", "jwt attack", "oauth attack",
    "broken authentication", "broken access control", "insecure deserialization",
    "csrf token", "api security", "graphql", "websocket", "directory listing",
    "robots.txt", "subdomain takeover",
    "stored xss", "reflected xss", "blind sqli", "boolean based", "time based",
    "union based", "csrf attack", "ssrf attack", "lfi attack", "rfi attack",
    "scanner", "scanners", "scanning", "rate limited", "rate limiting",
    "bug", "bugs", "flaw", "flaws", "weakness", "weaknesses", "ثغرات", "ثغره"
]

FOLLOW_UP_TRIGGERS = [
    "why", "how", "how so", "can you explain", "continue", "tell me more",
    "compare", "show example", "what about", "and then", "then", "what next",
    "ليه", "ازاي", "طب ليه", "كمل", "اشرح اكتر", "ممكن مثال", "قارن",
    "بعد كده", "طيب وبعدها", "وبعدين", "كمان", "ايه كمان"
]

class IntentEngine:
    def __init__(self):
        pass

    def clean_text(self, text: str) -> str:
        if not text:
            return ""
        text = text.strip().lower()
        # Normalize Arabic Alifs (أ, إ, آ -> ا)
        text = re.sub(r"[أإآ]", "ا", text)
        text = re.sub(r"[?.,!؛؟]", "", text)
        # Strip Arabic definite article "ال" from start of words
        text = re.sub(r"\bال([أإآا-ي])", r"\1", text)
        return text

    def calculate_token_overlap(self, query: str, trigger: str) -> float:
        query_words = set(query.split())
        trigger_words = set(trigger.split())
        if not query_words or not trigger_words:
            return 0.0
        intersection = query_words.intersection(trigger_words)
        union = query_words.union(trigger_words)
        return len(intersection) / len(union)

    def is_substring_match(self, query: str, trigger: str) -> bool:
        """
        Whole-word / whole-phrase match with boundary checks, so that a short
        trigger like 'sql' does not incorrectly match inside a longer word
        like 'mysql'.
        """
        if trigger in query:
            idx = query.find(trigger)
            left_ok = (idx == 0 or query[idx-1].isspace() or query[idx-1] in ".,!?;:؛؟")
            right_ok = (idx + len(trigger) == len(query) or query[idx+len(trigger)].isspace() or query[idx+len(trigger)] in ".,!?;:؛؟")
            return left_ok and right_ok
        return False

    def calculate_fuzzy_match(self, query: str, trigger: str) -> float:
        return difflib.SequenceMatcher(None, query, trigger).ratio()

    def score_phrase(self, query: str, trigger: str) -> float:
        exact_score = 1.0 if query == trigger else 0.0
        whole_word_score = 1.0 if self.is_substring_match(query, trigger) else 0.0
        token_overlap = self.calculate_token_overlap(query, trigger)
        fuzzy_score = self.calculate_fuzzy_match(query, trigger)

        # Base weighted score: Exact (0.6) + Whole Word (0.2) + Token Overlap (0.1) + Fuzzy (0.1)
        score = (exact_score * 0.6) + (whole_word_score * 0.2) + (token_overlap * 0.1) + (fuzzy_score * 0.1)

        if exact_score > 0:
            return 1.0
        return score

    def expand_synonyms(self, text: str) -> str:
        expanded_tokens = [text]
        for standard, aliases in CYBER_SYNONYMS.items():
            if self.is_substring_match(text, standard):
                expanded_tokens.extend(aliases)
            for alias in aliases:
                if self.is_substring_match(text, alias):
                    expanded_tokens.append(standard)
        return " ".join(expanded_tokens)

    def classify(self, raw_query: str) -> dict:
        # 1. Code review detection (Must be checked first to support multiline coding inputs)
        raw_lower = raw_query.lower()
        has_code_markers = any(m in raw_lower for m in [
            "def ", "function", "var ", "const ", "let ", "import ", "require(",
            "class ", "select ", "insert ", "<?php", "include", "eval(",
            "public class", "using", "#include", "system.out", "printf(",
            "console.log(", "select *", "update", "delete from", "drop table"
        ])
        if has_code_markers and len(raw_query.splitlines()) >= 2:
            return {"intent": "code_review", "confidence": 0.90}

        cleaned = self.clean_text(raw_query)
        if not cleaned:
            return {"intent": "unknown", "confidence": 0.0}

        expanded = self.expand_synonyms(cleaned)

        is_out_of_scope_word = any(word in cleaned for word in [
            "pizza", "recipe", "cook", "food", "poem", "poetry", "calculate", "math",
            "calculator", "football", "soccer", "player", "weather", "music", "song",
            "movie", "film", "joke", "بيتزا", "وصفة", "طبخ", "شعر", "قصيدة", "احسب",
            "رياضيات", "حساب", "كرة قدم", "كورة", "لاعب", "افضل لاعب", "طقس",
            "موسيقى", "اغنية", "فيلم", "نكتة"
        ])

        # Calculate intent scores
        scores = {}
        for intent, triggers in INTENT_TRIGGERS.items():
            max_phrase_score = 0.0
            for trigger in triggers:
                phrase_score = self.score_phrase(expanded, trigger)
                if phrase_score > max_phrase_score:
                    max_phrase_score = phrase_score

            # Apply Keyword Boost
            boost = 0.0
            if intent == "out_of_scope" and is_out_of_scope_word:
                boost = 0.15
            elif intent == "security_definition" and any(self.is_substring_match(expanded, word) for word in SECURITY_TRIGGERS):
                boost = 0.15
            elif intent == "mitigation_advice" and any(self.is_substring_match(expanded, word) for word in SECURITY_TRIGGERS):
                boost = 0.15
            elif intent == "attack_stats" and (any(self.is_substring_match(expanded, word) for word in ["how many", "count", "كم عدد", "كم هجمة"]) or re.search(r"\bكم\b", expanded)):
                boost = 0.15
            elif intent == "system_status" and any(self.is_substring_match(expanded, word) for word in ["stats", "status", "health", "dashboard", "احصائيات", "تقرير"]):
                boost = 0.15

            scores[intent] = min(max_phrase_score + boost, 1.0)

        # Find highest scoring intent
        best_intent = "unknown"
        best_score = 0.0
        for intent, score in scores.items():
            if score > best_score:
                best_score = score
                best_intent = intent

        if is_out_of_scope_word:
            is_security_q = any(self.is_substring_match(expanded, word) for word in SECURITY_TRIGGERS)
            is_cyber_synonym = any(any(self.is_substring_match(expanded, alias) for alias in aliases) for aliases in CYBER_SYNONYMS.values())
            if not (is_security_q or is_cyber_synonym):
                return {"intent": "out_of_scope", "confidence": 0.95}

        # Threshold check
        if best_score < 0.75:
            # Fall back to heuristics

            is_stats_word = any(self.is_substring_match(expanded, word) for word in ["stats", "status", "overview", "dashboard", "احصائيات", "تقرير", "الوضع", "كم عدد", "عدد هجمات", "كام", "كم هجمة"]) or re.search(r"\bكم\b", expanded)
            if is_stats_word:
                is_cyber_synonym = any(any(self.is_substring_match(expanded, alias) for alias in aliases) for aliases in CYBER_SYNONYMS.values())
                if is_cyber_synonym:
                    return {"intent": "attack_stats", "confidence": 0.85}
                return {"intent": "system_status", "confidence": 0.85}

            is_security_q = any(self.is_substring_match(expanded, word) for word in SECURITY_TRIGGERS)
            is_cyber_synonym = any(any(self.is_substring_match(expanded, alias) for alias in aliases) for aliases in CYBER_SYNONYMS.values())
            if is_security_q or is_cyber_synonym:
                is_mitigation = any(self.is_substring_match(expanded, word) for word in ["fix", "prevent", "secure code", "mitigate", "remediate", "علاج", "الوقاية", "علاجها", "حلها"])
                if is_mitigation:
                    return {"intent": "mitigation_advice", "confidence": 0.85}
                return {"intent": "security_definition", "confidence": 0.85}

            is_follow_up = any(self.is_substring_match(expanded, word) for word in FOLLOW_UP_TRIGGERS)
            if is_follow_up:
                return {"intent": "follow_up", "confidence": 0.75}

            return {"intent": "unknown", "confidence": best_score}

        return {"intent": best_intent, "confidence": best_score}

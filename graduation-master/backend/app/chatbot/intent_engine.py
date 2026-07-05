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
        "حالة النظام", "اخبار النظام", "ايه الاخبار"
    ],
    "top_attacker": [
        "top attacker", "top ip", "worst ip", "most active attacker",
        "most dangerous ip", "who is attacking us", "which ip is attacking",
        "اعلى مهاجم", "اكتر ip بيحاول يخترق", "المهاجم الرئيسي"
    ],
    "recent_threats": [
        "recent threats", "recent attacks", "what happened recently",
        "latest incidents", "latest logs", "recent blocked requests",
        "اخر الهجمات", "الهجمات الاخيرة", "الحوادث الاخيرة"
    ],
    "payload_analysis": [
        "analyze", "payload", "decode", "explain log", "malicious payload",
        "what is this query", "explain request",
        "حلل", "افحص البيلود", "فك التشفير", "تحليل الكود"
    ],
    "incident_query": [
        "incident", "why was it blocked", "investigate", "tell me about this incident",
        "why block", "incident details", "why did virex block this",
        "الحادثة", "ليه اتحجبت", "سبب الحظر", "تفاصيل الحادثة"
    ],
    "code_review": [
        "code review", "review code", "check code", "is this safe", "vulnerable code",
        "مراجعة الكود", "فحص الكود", "هل الكود امن"
    ],
    "mitigation_advice": [
        "how to fix", "how to prevent", "secure code example", "mitigate", "remediate",
        "prevent", "fix", "secure implementation", "how do i stop",
        "كيفية الاصلاح", "طريقة العلاج", "مثال برمجي امن", "كيف امنع"
    ]
}

CYBER_SYNONYMS = {
    "sqli": ["sql", "sql injection", "database injection", "union select", "sql query", "حقن استعلامات"],
    "xss": ["cross site scripting", "script injection", "cross-site scripting", "alert(", "onload", "حقن سكريبت"],
    "ssrf": ["server side request forgery", "server-side request forgery", "metadata query", "file://", "تزوير الطلبات من جهة الخادم"],
    "csrf": ["cross site request forgery", "cross-site request forgery", "xsrf", "missing csrf", "تزوير الطلبات عبر المواقع"],
    "brute": ["brute force", "login guessing", "repeated logins", "password attack", "تخمين كلمة المرور"],
    "scanner": ["nikto", "nmap", "gobuster", "sqlmap", "reconnaissance", "scanning", "فحص الثغرات"],
    "rate_limit": ["rate limiting", "ddos", "dos", "too many requests", "sliding window", "تحديد معدل الطلبات"]
}

SECURITY_TRIGGERS = [
    "explain", "what is", "how to prevent", "mitigate", "remediate", "cwe", "owasp", "cve",
    "secure coding", "how does it work", "vulnerability", "threat", "attack",
    "ثغرة", "كيف يعمل", "شرح", "كيفية الوقاية", "علاج", "حقن", "تخطي"
]

FOLLOW_UP_TRIGGERS = [
    "why", "how", "show example", "explain more", "give me an example", "compare", "which is worse",
    "ليه", "ازاي", "اعطيني مثال", "اشرح اكتر", "مقارنة"
]

class IntentEngine:
    def __init__(self):
        pass

    def clean_text(self, text: str) -> str:
        if not text:
            return ""
        text = text.strip().lower()
        text = re.sub(r"[?.,!؛؟]", "", text)
        return text

    def calculate_overlap(self, text: str, triggers: list) -> float:
        text_words = set(text.split())
        if not text_words:
            return 0.0
        max_score = 0.0
        for trigger in triggers:
            trigger_words = set(trigger.split())
            if not trigger_words:
                continue
            intersection = text_words.intersection(trigger_words)
            # Soft Jaccard index: penalize matches in long texts unless trigger matches most of it
            score = len(intersection) / (len(trigger_words) + 0.3 * (len(text_words) - len(intersection)))
            if score > max_score:
                max_score = score
        return max_score

    def fuzzy_match(self, text: str, triggers: list) -> float:
        max_score = 0.0
        for trigger in triggers:
            ratio = difflib.SequenceMatcher(None, text, trigger).ratio()
            if ratio > max_score:
                max_score = ratio
        return max_score

    def expand_synonyms(self, text: str) -> str:
        expanded = text
        for standard, aliases in CYBER_SYNONYMS.items():
            for alias in aliases:
                if alias in text:
                    expanded += f" {standard}"
        return expanded

    def classify(self, raw_query: str) -> dict:
        cleaned = self.clean_text(raw_query)
        if not cleaned:
            return {"intent": "unknown", "confidence": 0.0}

        expanded = self.expand_synonyms(cleaned)
        
        # Calculate intent scores
        scores = {}
        for intent, triggers in INTENT_TRIGGERS.items():
            overlap = self.calculate_overlap(expanded, triggers)
            fuzzy = self.fuzzy_match(cleaned, triggers)
            # Combined score weight
            scores[intent] = (overlap * 0.7) + (fuzzy * 0.3)

        # Find highest scoring intent
        best_intent = "unknown"
        best_score = 0.0
        for intent, score in scores.items():
            if score > best_score:
                best_score = score
                best_intent = intent

        # Heuristics for special types of intent
        # 1. Follow-up detection
        if best_score < 0.4:
            is_follow_up = any(word in cleaned for word in FOLLOW_UP_TRIGGERS)
            if is_follow_up:
                return {"intent": "follow_up", "confidence": 0.75}

        # 2. General security theory or definition question
        is_security_q = any(word in cleaned for word in SECURITY_TRIGGERS)
        is_cyber_synonym = any(any(alias in cleaned for alias in aliases) for aliases in CYBER_SYNONYMS.values())
        if best_score < 0.4 and (is_security_q or is_cyber_synonym):
            # Check if it asks for fix or mitigation
            is_mitigation = any(word in cleaned for word in ["fix", "prevent", "secure code", "mitigate", "remediate", "علاج", "الوقاية"])
            if is_mitigation:
                return {"intent": "mitigation_advice", "confidence": 0.85}
            return {"intent": "security_definition", "confidence": 0.85}

        # 3. Code review detection
        has_code_markers = any(m in raw_query for m in [
            "def ", "function", "var ", "const ", "let ", "import ", "require(",
            "class ", "select ", "insert ", "<?php", "include", "eval("
        ])
        if has_code_markers and len(raw_query.splitlines()) > 2:
            return {"intent": "code_review", "confidence": 0.90}

        # Minimum confidence threshold
        if best_score < 0.25:
            return {"intent": "unknown", "confidence": best_score}

        return {"intent": best_intent, "confidence": round(best_score, 2)}

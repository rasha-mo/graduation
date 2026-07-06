import random

identity_ar = [
    "أنا Dobby، مساعد الأمان الذكي المدمج في جدار الحماية Virex WAF. يمكنني تحليل الثغرات وفحص البيلود وعرض إحصائيات السيرفر.",
    "اسمي Dobby، رفيق الحماية الخاص بك في منصة Virex. وظيفتي هي تحليل الملفات الضارة ومراقبة أمن الشبكة ومساعدتك في معالجة الحوادث."
]
identity_en = [
    "I am Dobby, the built-in AI Security Assistant for Virex WAF. I specialize in real-time SIEM analytics, payload heuristics, and vulnerability remediation.",
    "I am Dobby, your virtual cybersecurity co-pilot. I analyze request signatures, summarize security logs, and suggest code fixes."
]

def get_identity_response(lang: str) -> str:
    if lang == "both":
        ar_resp = get_identity_response("ar")
        en_resp = get_identity_response("en")
        return f"{en_resp}\n\n---\n\n{ar_resp}"
    if lang == "ar":
        return random.choice(identity_ar)
    return random.choice(identity_en)

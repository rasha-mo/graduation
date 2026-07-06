import random

greetings_ar = [
    "مرحباً بك! أنا مساعد الحماية الذكي Dobby لمشروع Virex. كيف يمكنني مساعدتك اليوم؟ 🛡️",
    "أهلاً وسهلاً! Dobby في الخدمة لحماية نظامك. ما الذي تريد فحصه اليوم؟ 🛡️",
    "مرحباً! يسعدني مساعدتك في تأمين تطبيقاتك ومراقبة التهديدات. تفضل بسؤالي. 🛡️"
]
greetings_en = [
    "Hello! I am Dobby, your Virex WAF Security Co-pilot. How can I assist you with threat analysis today? 🛡️",
    "Welcome! Dobby is ready to help secure your system. What can I analyze for you today? 🛡️",
    "Greetings! Glad to help you monitor and secure your system. Ask me anything about WAF/SIEM. 🛡️"
]

how_are_you_ar = [
    "أنا بخير وأعمل بكامل طاقتي لمراقبة وحماية النظام! كيف يمكنني مساعدتك اليوم؟ 🛡️",
    "في أفضل حالاتي! محرك الحماية والـ Heuristics يعملان بأعلى كفاءة لمراقبة الهجمات."
]
how_are_you_en = [
    "I'm doing great and running at full capacity to protect the system! How can I assist you today? 🛡️",
    "Excellent! All security heuristic filters and models are online and monitoring traffic."
]

thanks_ar = [
    "على الرحب والسعة! أنا دائماً هنا لحمايتك ومساعدتك. 🛡️",
    "لا شكر على واجب! حماية نظامك هي أولويتي الكبرى. 🛡️",
    "يسعدني جداً تقديم المساعدة! ابقَ آمناً دائماً. 🛡️"
]
thanks_en = [
    "You're very welcome! I'm always here to help keep things secure. 🛡️",
    "Anytime! Ensuring your system's safety is my top priority. 🛡️",
    "Happy to help! Stay secure out there. 🛡️"
]

goodbye_ar = [
    "مع السلامة! ابقَ آمناً ولا تتردد في التحدث إليّ في أي وقت. 🛡️",
    "إلى اللقاء! رافقتك السلامة السيبرانية دائماً. 🛡️",
    "في أمان الله! تأكد من إبقاء جدار الحماية نشطاً دائماً. 🛡️"
]
goodbye_en = [
    "Goodbye! Stay safe and feel free to reach out anytime. 🛡️",
    "Farewell! Keep your WAF shields up and stay secure. 🛡️",
    "See you! Safe browsing, and I'll be here monitoring the dashboard. 🛡️"
]

def get_greeting_response(intent: str, lang: str) -> str:
    if lang == "both":
        ar_resp = get_greeting_response(intent, "ar")
        en_resp = get_greeting_response(intent, "en")
        return f"{en_resp}\n\n---\n\n{ar_resp}"
        
    if lang == "ar":
        if intent == "greeting":
            return random.choice(greetings_ar)
        elif intent == "how_are_you":
            return random.choice(how_are_you_ar)
        elif intent == "thanks":
            return random.choice(thanks_ar)
        elif intent == "goodbye":
            return random.choice(goodbye_ar)
    else:
        if intent == "greeting":
            return random.choice(greetings_en)
        elif intent == "how_are_you":
            return random.choice(how_are_you_en)
        elif intent == "thanks":
            return random.choice(thanks_en)
        elif intent == "goodbye":
            return random.choice(goodbye_en)
    return "Hello!"

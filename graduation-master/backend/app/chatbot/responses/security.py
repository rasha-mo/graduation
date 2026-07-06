import random

def get_security_response(lang: str, rag_context: str) -> str:
    """Local fallback explanation response if Gemini is offline."""
    if lang == "both":
        if rag_context:
            return "**Threat Details (English & Arabic):**\n\n" + rag_context
        return "I don't have reliable information about this topic. / لا أملك معلومات موثوقة عن هذا الموضوع داخل قاعدة المعرفة الحالية."
    elif lang == "ar":
        if rag_context:
            headers = [
                "**إليك تفاصيل الثغرة من قاعدة المعرفة المحلية:**\n\n",
                "**بناءً على دليل الأمان المدمج في النظام:**\n\n",
                "**لقد عثرت على الشرح التالي في قاعدة المعرفة المحلية:**\n\n"
            ]
            return random.choice(headers) + rag_context
        return "لا أملك معلومات موثوقة عن هذا الموضوع داخل قاعدة المعرفة الحالية."
    else:
        if rag_context:
            headers = [
                "**Here is the local knowledge base detail on this threat:**\n\n",
                "**According to our offline security database:**\n\n",
                "**I've retrieved the following threat description from the local database:**\n\n"
            ]
            return random.choice(headers) + rag_context
        return "I don't have reliable information about this topic."

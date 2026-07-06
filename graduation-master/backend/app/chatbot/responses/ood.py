def get_ood_response(lang: str) -> str:
    if lang == "both":
        ar_resp = get_ood_response("ar")
        en_resp = get_ood_response("en")
        return f"{en_resp}\n\n---\n\n{ar_resp}"
        
    if lang == "ar":
        return (
            "عذرًا، أنا Dobby، مساعد متخصص في الأمن السيبراني داخل نظام Virex، لذلك لا أستطيع الإجابة عن الأسئلة خارج هذا المجال.\n"
            "يمكنك سؤالي عن:\n"
            "• SQL Injection\n"
            "• XSS\n"
            "• CSRF\n"
            "• SSRF\n"
            "• Path Traversal\n"
            "• Brute Force\n"
            "• Secure Coding\n"
            "• WAF\n"
            "• SIEM\n"
            "• Logs\n"
            "• Payload Analysis\n"
            "• Incident Response\n"
            "• Threat Hunting"
        )
    else:
        return (
            "Sorry, I am Dobby, a cybersecurity assistant specialized in the Virex platform.\n"
            "I only answer cybersecurity-related questions."
        )

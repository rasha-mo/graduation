def get_payload_response(lang: str, payload_analysis: dict) -> str:
    if lang == "both":
        ar_resp = get_payload_response("ar", payload_analysis)
        en_resp = get_payload_response("en", payload_analysis)
        return f"{en_resp}\n\n---\n\n{ar_resp}"
        
    if not payload_analysis:
        if lang == "ar":
            return "لم يتم الكشف عن أي بيلود ضار في طلبك."
        return "No malicious payload was detected in your query."
        
    highest = payload_analysis.get("highest_severity", "Informational")
    detections = payload_analysis.get("detections", [])
    
    if lang == "ar":
        res = f"🚨 **تنبيه فاحص المدخلات المحلي (Local Payload Analyzer):**\n"
        res += f"- **مستوى الخطورة الأقصى**: {highest}\n"
        res += f"- **التهديدات المكتشفة**:\n"
        for det in detections:
            res += f"  * نوع التهديد: **{det.get('attack', 'غير معروف')}** | النمط المكتشف: `{det.get('pattern', 'غير معروف')}`\n"
        return res
    else:
        res = f"🚨 **Local Payload Heuristic Alert:**\n"
        res += f"- **Highest Severity**: {highest}\n"
        res += f"- **Detections**:\n"
        for det in detections:
            res += f"  * Attack Category: **{det.get('attack', 'Unknown')}** | Matched Signature: `{det.get('pattern', 'Unknown')}`\n"
        return res

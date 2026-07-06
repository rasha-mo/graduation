def get_incident_response(lang: str, incident_data: dict) -> str:
    if lang == "both":
        ar_resp = get_incident_response("ar", incident_data)
        en_resp = get_incident_response("en", incident_data)
        return f"{en_resp}\n\n---\n\n{ar_resp}"
        
    if not incident_data:
        if lang == "ar":
            return "لم يتم العثور على تفاصيل لهذه الحادثة."
        return "No incident details were found."
        
    if lang == "ar":
        return f"**تفاصيل الحادثة المعالجة:**\n" \
               f"- **معرف الحادثة**: {incident_data.get('id', 'غير معروف')}\n" \
               f"- **العنوان**: {incident_data.get('title', 'غير معروف')}\n" \
               f"- **الخطورة**: {incident_data.get('severity', 'غير معروف')}\n" \
               f"- **عنوان IP المهاجم**: {incident_data.get('attacker_ip', 'غير معروف')}\n"                f"- **رابط الاستهداف**: `{incident_data.get('request_uri', 'غير معروف')}`\n" \
               f"- **تاريخ ووقت الحظر**: {incident_data.get('timestamp', 'غير معروف')}\n" \
               f"- **الوصف**: {incident_data.get('description', 'لا يوجد وصف متاح')}"
    else:
        return f"**Selected Incident Details:**\n" \
               f"- **Incident ID**: {incident_data.get('id', 'Unknown')}\n" \
               f"- **Title**: {incident_data.get('title', 'Unknown')}\n" \
               f"- **Severity**: {incident_data.get('severity', 'Unknown')}\n" \
               f"- **Attacker IP**: {incident_data.get('attacker_ip', 'Unknown')}\n" \
               f"- **Request URI**: `{incident_data.get('request_uri', 'Unknown')}`\n" \
               f"- **Timestamp**: {incident_data.get('timestamp', 'Unknown')}\n" \
               f"- **Description**: {incident_data.get('description', 'No description available')}"

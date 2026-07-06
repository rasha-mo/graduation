def get_status_response(query: str, lang: str, stats: dict) -> str:
    # Always fetch stats directly from SecurityDashboard stats context passed down
    query_lower = query.lower()
    is_sql = any(alias in query_lower for alias in ["sql", "sqli", "injection", "استعلامات"])
    is_xss = any(alias in query_lower for alias in ["xss", "script", "سكريبت"])
    is_brute = any(alias in query_lower for alias in ["brute", "force", "guess", "تخمين", "قوة غاشمة"])
    is_scanner = any(alias in query_lower for alias in ["scanner", "scan", "فحص", "مكتشف"])
    if lang == "both":
        ar_resp = get_status_response(query, "ar", stats)
        en_resp = get_status_response(query, "en", stats)
        return f"{en_resp}\n\n---\n\n{ar_resp}"
        
    if lang == "ar":
        if is_sql:
            return f"عدد محاولات حقن SQL (SQL Injection) التي تم رصدها وحجبها هي: **{stats.get('sql_injection_attempts', 0)}** هجمة. 🛡️"
        elif is_xss:
            return f"عدد محاولات حقن السكريبتات العابرة للمواقع (XSS) التي تم رصدها وحجبها هي: **{stats.get('xss_attempts', 0)}** هجمة. 🛡️"
        elif is_brute:
            return f"عدد محاولات التخمين والقوة الغاشمة (Brute Force) التي تم رصدها وحجبها هي: **{stats.get('brute_force_attempts', 0)}** محاولة. 🛡️"
        elif is_scanner:
            return f"عدد محاولات فحص المنافذ والمسارات (Scanners) التي تم رصدها وحجبها هي: **{stats.get('scanner_attempts', 0)}** محاولة. 🛡️"
        else:
            return f"إليك تقرير إحصائيات النظام الفورية:\n" \
                   f"- **إجمالي الطلبات المستلمة**: {stats.get('total_requests', 0)}\n" \
                   f"- **الطلبات المحظورة (WAF Blocks)**: {stats.get('blocked_requests', 0)}\n" \
                   f"- **الطلبات النظيفة الممرة**: {stats.get('normal_requests', 0)}\n" \
                   f"- **محاولات حقن SQL (SQLi)**: {stats.get('sql_injection_attempts', 0)}\n" \
                   f"- **محاولات حقن سكريبتات (XSS)**: {stats.get('xss_attempts', 0)}\n" \
                   f"- **محاولات التخمين (Brute Force)**: {stats.get('brute_force_attempts', 0)}\n" \
                   f"- **محاولات فحص المسارات (Scanners)**: {stats.get('scanner_attempts', 0)}\n" \
                   f"- **تجاوز حد معدل الطلبات (Rate Limiting)**: {stats.get('rate_limit_hits', 0)}\n" \
                   f"- **اكتشافات الذكاء الاصطناعي (ML)**: {stats.get('ml_detections', 0)}\n" \
                   f"- **المهاجم الأكثر نشاطاً**: `{stats.get('top_attacker_ip', 'لا يوجد')}` (بعدد {stats.get('top_attacker_count', 0)} هجمة)"
    else:
        if is_sql:
            return f"The number of SQL Injection (SQLi) attempts detected and blocked is: **{stats.get('sql_injection_attempts', 0)}** attacks. 🛡️"
        elif is_xss:
            return f"The number of Cross-Site Scripting (XSS) attempts detected and blocked is: **{stats.get('xss_attempts', 0)}** attacks. 🛡️"
        elif is_brute:
            return f"The number of Brute Force attempts detected and blocked is: **{stats.get('brute_force_attempts', 0)}** attempts. 🛡️"
        elif is_scanner:
            return f"The number of Scanner/Recon probes detected and blocked is: **{stats.get('scanner_attempts', 0)}** probes. 🛡️"
        else:
            return f"Here is the system health and statistics overview:\n" \
                   f"- **Total Requests**: {stats.get('total_requests', 0)}\n" \
                   f"- **WAF Blocked**: {stats.get('blocked_requests', 0)}\n" \
                   f"- **Clean Requests**: {stats.get('normal_requests', 0)}\n" \
                   f"- **SQL Injection Attempts**: {stats.get('sql_injection_attempts', 0)}\n" \
                   f"- **XSS Attempts**: {stats.get('xss_attempts', 0)}\n" \
                   f"- **Brute Force Attempts**: {stats.get('brute_force_attempts', 0)}\n" \
                   f"- **Scanner/Recon Probes**: {stats.get('scanner_attempts', 0)}\n" \
                   f"- **Rate Limit Hits**: {stats.get('rate_limit_hits', 0)}\n" \
                   f"- **ML Engine Detections**: {stats.get('ml_detections', 0)}\n"                    f"- **Top Attacker**: `{stats.get('top_attacker_ip', 'None')}` ({stats.get('top_attacker_count', 0)} attempts)"

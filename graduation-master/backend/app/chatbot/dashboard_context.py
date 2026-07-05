"""
Virex AI Assistant — SIEM Dashboard Context Collector
"""
import logging

logger = logging.getLogger(__name__)

class DashboardContextCollector:
    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance

    def collect(self) -> dict:
        """
        Gathers live stats directly from the dashboard database and stats cache
        to feed the AI Assistant with real-time SIEM statistics.
        """
        stats = {}
        try:
            # Load fresh SIEM stats from the services Layer
            data = self.dashboard.get_dashboard_data() or {}
            db_stats = data.get("stats", {})
            
            # Extract main metrics
            stats["total_requests"] = db_stats.get("total_requests", self.dashboard.stats.get("total_requests", 0))
            stats["blocked_requests"] = db_stats.get("blocked_requests", self.dashboard.stats.get("blocked_requests", 0))
            stats["normal_requests"] = db_stats.get("normal_requests_count", self.dashboard.stats.get("normal_requests_count", 0))
            stats["rate_limit_hits"] = db_stats.get("rate_limit_hits", self.dashboard.stats.get("rate_limit_hits", 0))
            stats["ml_detections"] = db_stats.get("ml_detections", self.dashboard.stats.get("ml_detections", 0))
            
            # Specific WAF attack category statistics
            stats["sql_injection_attempts"] = db_stats.get("sql_injection_attempts", 0)
            stats["xss_attempts"] = db_stats.get("xss_attempts", 0)
            stats["brute_force_attempts"] = db_stats.get("brute_force_attempts", 0)
            stats["scanner_attempts"] = db_stats.get("scanner_attempts", 0)
            stats["path_traversal_attempts"] = db_stats.get("path_traversal_attempts", 0)
            stats["cmd_injection_attempts"] = db_stats.get("command_injection_attempts", 0)
            
            # Fetch recent timeline and threats list
            stats["recent_threats_count"] = len(data.get("recent_threats", []))
            
            # Calculate top attacker and targeted endpoints
            threats = data.get("recent_threats", [])
            ip_counts = {}
            endpoint_counts = {}
            for t in threats:
                ip = t.get("ip") or t.get("source_ip")
                if ip and ip not in ("Unknown", "XXX.XXX.XXX.XXX"):
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                
                ep = t.get("endpoint") or t.get("path")
                if ep:
                    endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1
            
            stats["top_attacker_ip"] = max(ip_counts, key=ip_counts.get) if ip_counts else "None detected"
            stats["top_attacker_count"] = ip_counts.get(stats["top_attacker_ip"], 0) if ip_counts else 0
            
            stats["top_targeted_endpoint"] = max(endpoint_counts, key=endpoint_counts.get) if endpoint_counts else "None"
            stats["top_targeted_count"] = endpoint_counts.get(stats["top_targeted_endpoint"], 0) if endpoint_counts else 0
            
        except Exception as e:
            logger.error(f"[DASHBOARD CONTEXT] Failed to gather stats: {e}", exc_info=True)
            # Fallback to local stats dictionary if the main DB retrieval crashes
            s = getattr(self.dashboard, "stats", {})
            stats = {
                "total_requests": s.get("total_requests", 0),
                "blocked_requests": s.get("blocked_requests", 0),
                "normal_requests": s.get("normal_requests_count", 0),
                "rate_limit_hits": s.get("rate_limit_hits", 0),
                "ml_detections": s.get("ml_detections", 0),
                "sql_injection_attempts": s.get("sql_injection_attempts", 0),
                "xss_attempts": s.get("xss_attempts", 0),
                "brute_force_attempts": s.get("brute_force_attempts", 0),
                "top_attacker_ip": "Unavailable",
                "top_targeted_endpoint": "Unavailable"
            }
            
        return stats

    def format_to_text(self, stats: dict, lang: str = "en") -> str:
        if lang == "ar":
            return f"""
إحصائيات النظام الفورية الحالية:
- إجمالي الطلبات المستلمة: {stats.get('total_requests', 0)}
- الطلبات المحظورة (WAF Blocks): {stats.get('blocked_requests', 0)}
- الطلبات النظيفة الممرة: {stats.get('normal_requests', 0)}
- محاولات حقن SQL (SQLi): {stats.get('sql_injection_attempts', 0)}
- محاولات حقن سكريبتات (XSS): {stats.get('xss_attempts', 0)}
- محاولات التخمين (Brute Force): {stats.get('brute_force_attempts', 0)}
- محاولات فحص المنافذ والمنافذ الحساسة: {stats.get('scanner_attempts', 0)}
- تجاوز حد معدل الطلبات (Rate Limiting): {stats.get('rate_limit_hits', 0)}
- اكتشافات الذكاء الاصطناعي الشاذة (ML Anomaly Detections): {stats.get('ml_detections', 0)}
- عنوان المهاجم الأكثر نشاطاً: {stats.get('top_attacker_ip', 'لا يوجد')} (بعدد {stats.get('top_attacker_count', 0)} هجمة)
- الصفحة الأكثر استهدافاً: {stats.get('top_targeted_endpoint', 'لا يوجد')}
"""
        return f"""
Current Live System Statistics:
- Total Requests Received: {stats.get('total_requests', 0)}
- Blocked Requests (WAF Blocks): {stats.get('blocked_requests', 0)}
- Clean Requests Forwarded: {stats.get('normal_requests', 0)}
- SQL Injection Attempts: {stats.get('sql_injection_attempts', 0)}
- XSS (Cross-Site Scripting) Attempts: {stats.get('xss_attempts', 0)}
- Brute Force Login Attempts: {stats.get('brute_force_attempts', 0)}
- Scanner / Recon Probes: {stats.get('scanner_attempts', 0)}
- Rate Limit Hits (HTTP 429): {stats.get('rate_limit_hits', 0)}
- ML Engine Detections: {stats.get('ml_detections', 0)}
- Top Attacking Source IP: {stats.get('top_attacker_ip', 'None')} ({stats.get('top_attacker_count', 0)} attempts)
- Most Targeted Path/Endpoint: {stats.get('top_targeted_endpoint', 'None')}
"""

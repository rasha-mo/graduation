"""
Virex AI Assistant — Payload Analysis Wrapper Service
"""
import logging
from app.chatbot.payload_analyzer import analyze_payload

logger = logging.getLogger(__name__)

class PayloadService:
    def __init__(self):
        pass

    def inspect(self, raw_input: str) -> dict | None:
        """
        Runs local heuristic regex matching to identify if the input query
        resembles a malicious log, exploit payload, or unsafe web query parameters.
        """
        if not raw_input or len(raw_input) < 10:
            return None
            
        try:
            analysis = analyze_payload(raw_input)
            if analysis and analysis.get("is_malicious"):
                return analysis
        except Exception as e:
            logger.error(f"[PAYLOAD SERVICE] Failed to analyze payload: {e}")
            
        return None

    def format_to_text(self, analysis: dict, lang: str = "en") -> str:
        if not analysis:
            return ""

        detections = analysis.get("detections", [])
        categories = [d["attack"] for d in detections]
        severity = analysis.get("highest_severity", "ℹ️ Info")

        if lang == "ar":
            return f"""
تحليل البيلود البرمجي المكتشف محلياً:
- مستوى الخطورة: {severity}
- التهديدات المكتشفة: {', '.join(categories)}
- هل المحتوى خبيث؟ نعم (أنماط هجومية مؤكدة).
"""
        return f"""
Locally Detected Exploitation Signature:
- Severity level: {severity}
- Identified Threats: {', '.join(categories)}
- Is Malicious: Yes (Highly suspicious pattern matched).
"""

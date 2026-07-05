"""
Virex AI Assistant — Response Formatting Service
"""
import re
import logging

logger = logging.getLogger(__name__)

class ResponseFormatter:
    def __init__(self):
        pass

    def format_code_block(self, code: str, language: str = "python") -> str:
        """Helper to safely format code blocks."""
        return f"\n```{language}\n{code.strip()}\n```\n"

    def ensure_markdown_aesthetics(self, response: str) -> str:
        """
        Post-processes responses to ensure high-quality markdown layout
        with clean bullet points, tables, and sections.
        """
        if not response:
            return ""

        # Enforce bolding on bullet keywords (e.g. "Fix:", "Vulnerability:")
        keywords = ["Fix:", "Vulnerability:", "Risk:", "Description:", "CWE:", "OWASP:", "الحل:", "الوصف:", "الخطورة:"]
        for kw in keywords:
            response = re.sub(rf"\b{kw}\b", f"**{kw}**", response)

        # Remove duplicate consecutive newlines
        response = re.sub(r"\n{3,}", "\n\n", response)
        return response.strip()

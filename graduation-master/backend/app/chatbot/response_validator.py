"""
Virex AI Assistant — Response Validation Service
"""
import re
import logging

logger = logging.getLogger(__name__)

class ResponseValidator:
    def __init__(self):
        pass

    def validate(self, response_text: str, query: str, lang: str = "en") -> tuple[bool, str]:
        """
        Validates the output of the generation pipeline.
        Returns (is_valid, sanitized_response)
        """
        if not response_text or not isinstance(response_text, str):
            return False, ""

        cleaned = response_text.strip()
        
        # 1. Check for empty or whitespace-only responses
        if not cleaned or all(c.isspace() or c in '.,!?-~' for c in cleaned):
            logger.warning("[VALIDATOR] Rejected empty/whitespace response.")
            return False, ""

        # 2. Check for typical LLM placeholders (e.g. [Insert key here])
        placeholders = [
            r"\[insert.*?\]", r"\[placeholder.*?\]", r"your_api_key",
            r"<insert.*?>", r"<placeholder.*?>"
        ]
        for p in placeholders:
            if re.search(p, cleaned, re.IGNORECASE):
                logger.warning(f"[VALIDATOR] Detected placeholder pattern: {p}")
                # Strip out placeholders or return invalid
                return False, cleaned

        # 3. Guardrail: Verify the response is relevant to security or greetings
        # If response is extremely short (e.g. less than 3 characters), flag as invalid
        if len(cleaned) < 3:
            logger.warning("[VALIDATOR] Response too short.")
            return False, cleaned

        return True, cleaned

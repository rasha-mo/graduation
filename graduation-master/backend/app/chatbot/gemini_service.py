"""
Virex AI Assistant — Google Gemini Integration Service
"""
import os
import logging

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.has_gemini = False
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.has_gemini = True
            except ImportError:
                logger.error("[GEMINI SERVICE] Google GenerativeAI package not installed.")

    def is_available(self) -> bool:
        return self.has_gemini and bool(os.getenv("GEMINI_API_KEY"))

    def ask(self, system_instruction: str, query: str, history: list = None) -> str | None:
        """
        Sends the query and conversational context to Gemini 1.5 Flash.
        Uses a temperature of 0.7 to maximize diversity of answers, avoiding repetitive phrasing.
        """
        if not self.is_available():
            return None

        try:
            import google.generativeai as genai
            
            # Configure Generation settings for rich diversity and high security expertise
            generation_config = {
                "temperature": 0.75, # Balanced creativity to diversify output phrasing and formatting
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 2048,
            }

            model = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                system_instruction=system_instruction,
                generation_config=generation_config
            )

            prompt_content = []
            
            # Append trailing conversation history (up to last 10 messages for memory limits)
            if history:
                history_text = "Prior Chat Memory Context:\n"
                for msg in history[-10:]:
                    role_label = "User" if msg.get("role") == "user" else "Assistant"
                    history_text += f"{role_label}: {msg.get('content')}\n"
                prompt_content.append(history_text)

            prompt_content.append(f"User Query: {query}")

            response = model.generate_content("\n".join(prompt_content))
            if response and response.text:
                return response.text.strip()
                
        except Exception as e:
            logger.error(f"[GEMINI SERVICE] Generation failed: {e}", exc_info=True)
            
        return None

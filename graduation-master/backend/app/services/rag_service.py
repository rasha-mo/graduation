"""
RAG Service Logic

Handles embedding, retrieving, and generating AI responses.
"""
import logging
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

from app.models.rag_knowledge import KNOWLEDGE_BASE, SECURITY_KEYWORDS

logger = logging.getLogger(__name__)

# We use huggingface transformers and sentence-transformers for a free AI setup.
try:
    from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
    from sentence_transformers import SentenceTransformer
except ImportError:
    logger.error("Missing RAG dependencies. Run: pip install transformers sentence-transformers torch")
    AutoTokenizer = None
    AutoModelForSeq2SeqLM = None
    SentenceTransformer = None

class SecurityRAGService:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        """Singleton pattern so we don't load huge models on every request."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        if not AutoTokenizer or not AutoModelForSeq2SeqLM or not SentenceTransformer:
            raise RuntimeError("Required ML libraries are not installed.")
            
        logger.info("Initializing Security RAG Service...")
        
        # 1. Initialize the embedding model
        logger.info("Loading Embedding Model...")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        # 2. Initialize the generative LLM
        logger.info("Loading Generative AI Model...")
        self.tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-small")
        self.model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-small")
        
        # 3. Compute embeddings for the knowledge base
        logger.info("Computing Knowledge Base Embeddings...")
        self.document_texts = [f"{doc['title']}: {doc['content']}" for doc in KNOWLEDGE_BASE]
        self.document_embeddings = self.embedder.encode(self.document_texts)
        
        logger.info("Security RAG Service Ready!")
        
    def is_security_question(self, query):
        """Guardrail check to ensure the query is related to security."""
        query_lower = query.lower()
        return any(keyword in query_lower for keyword in SECURITY_KEYWORDS)

    def retrieve(self, query, top_k=2):
        """Retrieve the most relevant context from the knowledge base."""
        query_embedding = self.embedder.encode([query])
        similarities = cosine_similarity(query_embedding, self.document_embeddings)[0]
        
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        if similarities[top_indices[0]] < 0.2:
            return None
            
        retrieved_docs = [self.document_texts[i] for i in top_indices]
        return " | ".join(retrieved_docs)

    def generate_response(self, query):
        """Generates an answer to the query using the RAG pipeline."""
        if not self.is_security_question(query):
            return "SECURITY RESTRICTION: I am a specialized AI for cybersecurity. I can only answer questions related to security, attacks, bugs, and vulnerabilities."
            
        # 1. Normalize query
        query_norm = query.strip().lower().rstrip('?.!')
        
        # Check if query contains Arabic characters
        has_arabic = any('\u0600' <= char <= '\u06FF' for char in query_norm)
        
        # 2. Check for friendly greetings
        greetings = {'hi', 'hello', 'hey', 'greetings', 'hello there', 'hi there'}
        if query_norm in greetings:
            return "Hello! I am the VIREX Security Assistant. I can help you understand security vulnerabilities, attacks, and WAF rules. How can I help you today?"
            
        # 3. Apply keyword rewrites for short or unstructured inputs
        keyword_rewrites = {
            "xss": "What is Cross-Site Scripting (XSS)?",
            "what xss": "What is Cross-Site Scripting (XSS)?",
            "sqli": "What is SQL Injection (SQLi)?",
            "sql injection": "What is SQL Injection (SQLi)?",
            "sql": "What is SQL Injection (SQLi)?",
            "what sqli": "What is SQL Injection (SQLi)?",
            "csrf": "What is Cross-Site Request Forgery (CSRF)?",
            "what csrf": "What is Cross-Site Request Forgery (CSRF)?",
            "ssrf": "What is Server-Side Request Forgery (SSRF)?",
            "what ssrf": "What is Server-Side Request Forgery (SSRF)?",
            "brute force": "What is Brute Force Attacks?",
            "rate limit": "What is Rate Limiting?",
            "rate limiting": "What is Rate Limiting?",
            "scanner": "What are Security Scanners?",
            "scanning": "What are Security Scanners?",
            "path traversal": "What is Path Traversal (Directory Traversal)?",
            "directory traversal": "What is Path Traversal (Directory Traversal)?",
            "command injection": "What is OS Command Injection?",
            "broken authentication": "What is Broken Authentication?",
            "broken auth": "What is Broken Authentication?",
            "session management": "What is Broken Session Management?",
            
            # Arabic keyword rewrites
            "تحديد معدل الطلبات": "ما هو تحديد معدل الطلبات (Rate Limiting)؟",
            "معدل الطلبات": "ما هو تحديد معدل الطلبات (Rate Limiting)؟",
            "تخمين": "ما هي هجمات القوة الغاشمة (Brute Force)؟",
            "قوة غاشمة": "ما هي هجمات القوة الغاشمة (Brute Force)؟",
            "حقن الأوامر": "ما هو حقن أوامر نظام التشغيل (Command Injection)؟",
            "حقن الاستعلامات": "ما هي ثغرة حقن استعلامات قاعدة البيانات (SQL Injection)؟",
            "تخطي المسار": "ما هي ثغرة تخطي مسارات المجلدات (Path Traversal)؟",
            "تزوير الطلبات": "ما هي ثغرة تزوير الطلبات عبر المواقع (CSRF)؟"
        }
        
        clean_query = query.strip()
        if query_norm in keyword_rewrites:
            clean_query = keyword_rewrites[query_norm]
        else:
            if has_arabic:
                arabic_question_words = ["ما", "كيف", "لماذا", "من", "شرح", "كيفية"]
                if not any(query_norm.startswith(word) for word in arabic_question_words):
                    clean_query = f"ما هو {clean_query}؟"
            else:
                english_question_words = ["what", "how", "why", "who", "define", "explain"]
                if not any(query_norm.startswith(word) for word in english_question_words):
                    clean_query = f"What is {clean_query}?"

        # Append English translation hints to clean_query if it contains Arabic terms
        # to assist the English-only sentence transformer (all-MiniLM-L6-v2) in mapping.
        arabic_to_english_terms = {
            "تحديد معدل الطلبات": "rate limiting",
            "معدل الطلبات": "rate limiting",
            "تخمين": "brute force",
            "قوة غاشمة": "brute force",
            "حقن الأوامر": "command injection",
            "حقن الاستعلامات": "sql injection",
            "حقن استعلامات": "sql injection",
            "تخطي المسار": "path traversal",
            "تخطي مسار": "path traversal",
            "تزوير الطلبات": "csrf",
            "مصادقة": "authentication",
            "جلسة": "session",
            "فحص": "scanner",
            "استطلاع": "reconnaissance"
        }
        for ar_term, en_term in arabic_to_english_terms.items():
            if ar_term in clean_query.lower():
                clean_query += f" ({en_term})"
                break
                
        # 4. Retrieve context using the cleaned query
        context = self.retrieve(clean_query)
        
        if not context:
            return "I'm sorry, but I can't provide additional information on this topic. My responses are limited to the information available in the provided knowledge base and applicable safety policies."
            
        # Bypass generation for Arabic queries as Flan-T5 is English-only and will hang/timeout
        if has_arabic:
            parts = context.split(" | ")
            fallback_parts = []
            for part in parts:
                if ":" in part:
                    title_part, content_body = part.split(":", 1)
                    fallback_parts.append(f"• {title_part.strip()}:\n{content_body.strip()}")
                else:
                    fallback_parts.append(f"• {part.strip()}")
            return "\n\n".join(fallback_parts)

        # 5. Format prompt using standard Q&A template (English only)
        prompt = (
            f"Context: {context}\n"
            f"Question: {clean_query}\n"
            f"Answer:"
        )
        
        inputs = self.tokenizer(prompt, return_tensors="pt")
        outputs = self.model.generate(**inputs, max_length=500)
        generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Check if the generated text is empty, whitespace-only, or composed of spaces
        is_empty_or_whitespace = (
            not generated_text or 
            generated_text.strip() == "" or 
            all(c.isspace() or c in '.,!?-~' for c in generated_text)
        )
        
        if not is_empty_or_whitespace:
            return generated_text.strip()
        else:
            # Fallback: Extract the parsed content from the retrieved context
            if context:
                parts = context.split(" | ")
                fallback_parts = []
                for part in parts:
                    if ":" in part:
                        # Split by first colon to separate Title and Content
                        title_part, content_body = part.split(":", 1)
                        # Only return the content details
                        fallback_parts.append(f"• {title_part.strip()}:\n{content_body.strip()}")
                    else:
                        fallback_parts.append(f"• {part.strip()}")
                return "\n\n".join(fallback_parts)
            return "Failed to generate a response."

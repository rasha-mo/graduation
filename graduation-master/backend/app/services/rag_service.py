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

    def retrieve(self, query, top_k=3):
        """Retrieve the most relevant context from the knowledge base with keyword boosting."""
        query_embedding = self.embedder.encode([query])
        similarities = cosine_similarity(query_embedding, self.document_embeddings)[0].copy()
        query_lower = query.lower()
        
        # concept group mapping to specific document indices in KNOWLEDGE_BASE
        concept_groups = [
            (["bug", "bugs", "vulnerabilit", "flaw", "weakness", "ثغرة", "ثغرات", "ثغره"], [0, 1]),
            (["sql", "sqli", "injection", "حقن"], [2, 3]),
            (["xss", "cross-site", "cross site", "scripting", "سكريبت"], [4, 5]),
            (["brute", "force", "guessing", "تخمين", "قوة غاشمة"], [6, 7]),
            (["scanner", "scanners", "scanning", "فحص", "استطلاع"], [8, 9]),
            (["rate limit", "rate limiting", "rate limited", "rate-limiting", "معدل", "طلبات", "تحديد"], [10, 11]),
            (["csrf", "xsrf", "تزوير"], [12, 13]),
            (["ssrf", "خادم", "سيرفر"], [14, 15]),
            (["path", "traversal", "directory", "مسار", "مجلد"], [16, 17]),
            (["command", "exec", "rce", "اوامر"], [18, 19]),
            (["auth", "login", "session", "jwt", "cookie", "مصادقة", "جلسة"], [20, 21])
        ]
        
        for kws, indices in concept_groups:
            if any(kw in query_lower for kw in kws):
                for idx in indices:
                    similarities[idx] += 2.0
                            
        # Sort indices by similarity descending
        sorted_indices = np.argsort(similarities)[::-1]
        
        # Enforce strict 0.45 similarity threshold
        valid_indices = [i for i in sorted_indices if similarities[i] >= 0.45]
        
        if not valid_indices:
            return "", 0.0
            
        top_indices = valid_indices[:top_k]
        max_similarity = float(similarities[top_indices[0]])
        
        retrieved_docs = []
        seen = set()
        for idx in top_indices:
            doc_text = self.document_texts[idx]
            if doc_text not in seen:
                seen.add(doc_text)
                retrieved_docs.append(doc_text)
                
        return "\n\n".join(retrieved_docs), max_similarity

    def generate_response(self, query):
        """Generates an answer to the query using the unified WAF AI co-pilot pipeline."""
        if not self.is_security_question(query):
            return "SECURITY RESTRICTION: I am a specialized AI for cybersecurity. I can only answer questions related to security, attacks, bugs, and vulnerabilities."
            
        try:
            from app.chatbot.dobby_chat import SecurityChatbot
            from flask import current_app
            db_service = None
            try:
                db_service = getattr(current_app, "db_service", None)
            except Exception:
                pass
                
            if not db_service:
                # Local mock context if outside active application server context
                class MockDashboard:
                    def __init__(self):
                        self.stats = {}
                        self.incidents = {}
                    def get_dashboard_data(self):
                        return {"stats": self.stats, "recent_threats": []}
                db_service = MockDashboard()
                
            bot = SecurityChatbot(db_service)
            return bot.generate_response(query, role="guest", username="guest")
        except Exception as e:
            logger.error(f"[RAG SERVICE] Failed to execute reasoner: {e}")
            return "An internal error occurred while processing your request."

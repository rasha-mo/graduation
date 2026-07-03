import os
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

# We use huggingface transformers and sentence-transformers for a free AI setup.
try:
    from transformers import pipeline
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("Please install the required libraries by running:")
    print("pip install transformers sentence-transformers torch")
    exit(1)

class SecurityRAGSystem:
    def __init__(self):
        """
        Initializes the Retrieval-Augmented Generation (RAG) System.
        Uses completely free models from Hugging Face.
        """
        # 1. Initialize the embedding model for retrieving knowledge (Free from Hugging Face)
        print("Loading Embedding Model...")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        # 2. Initialize the generative LLM for answering questions (Free from Hugging Face)
        # google/flan-t5-base is a great open-source model for QA tasks.
        print("Loading Generative AI Model...")
        self.generator = pipeline("text2text-generation", model="google/flan-t5-base")
        
        # 3. Knowledge Base: Attack Types, Bugs, and Vulnerabilities
        self.knowledge_base = [
            {
                "title": "SQL Injection (SQLi)",
                "content": "SQL Injection is an attack where malicious SQL statements are inserted into entry fields for execution. It allows attackers to spoof identity, tamper with existing data, cause repudiation issues, and access sensitive data.",
                "type": "Attack"
            },
            {
                "title": "Cross-Site Scripting (XSS)",
                "content": "XSS attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. It occurs when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.",
                "type": "Attack"
            },
            {
                "title": "Cross-Site Request Forgery (CSRF)",
                "content": "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. It targets state-changing requests, not theft of data.",
                "type": "Attack"
            },
            {
                "title": "Buffer Overflow",
                "content": "A buffer overflow occurs when a program or process attempts to write more data to a fixed length block of memory (a buffer) than the buffer is allocated to hold. This can lead to system crashes or arbitrary code execution.",
                "type": "Bug/Vulnerability"
            },
            {
                "title": "Broken Access Control",
                "content": "Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.",
                "type": "Bug/Vulnerability"
            },
            {
                "title": "Insecure Deserialization",
                "content": "Insecure deserialization often leads to remote code execution. Even if it does not result in remote code execution, it can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation.",
                "type": "Bug/Vulnerability"
            },
            {
                "title": "Denial of Service (DoS)",
                "content": "A Denial-of-Service (DoS) attack is meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash.",
                "type": "Attack"
            },
            {
                "title": "Path Traversal (Directory Traversal)",
                "content": "A path traversal attack aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with dot-dot-slash (../) sequences and its variations.",
                "type": "Attack/Bug"
            }
        ]
        
        # 4. Compute embeddings for the knowledge base
        print("Computing Knowledge Base Embeddings...")
        self.document_texts = [f"{doc['title']}: {doc['content']}" for doc in self.knowledge_base]
        self.document_embeddings = self.embedder.encode(self.document_texts)
        
        # 5. Security Guardrail Keywords
        self.security_keywords = [
            'security', 'attack', 'vulnerability', 'hack', 'exploit', 'injection', 
            'xss', 'csrf', 'buffer', 'overflow', 'malware', 'phishing', 'dos', 'ddos', 
            'payload', 'breach', 'auth', 'cyber', 'virus', 'traversal', 'deserialization'
        ]
        print("Security RAG System Ready!")
        
    def is_security_question(self, query):
        """
        Guardrail check to ensure the query is related to security.
        """
        query_lower = query.lower()
        return any(keyword in query_lower for keyword in self.security_keywords)

    def retrieve(self, query, top_k=2):
        """
        Retrieve the most relevant context from the knowledge base using semantic search.
        """
        query_embedding = self.embedder.encode([query])
        similarities = cosine_similarity(query_embedding, self.document_embeddings)[0]
        
        # Get top k indices sorted by similarity
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # If the highest similarity is too low, we don't have relevant context
        if similarities[top_indices[0]] < 0.2:
            return None
            
        retrieved_docs = [self.document_texts[i] for i in top_indices]
        return " | ".join(retrieved_docs)

    def generate_response(self, query):
        """
        Generates an answer to the query using the RAG pipeline.
        """
        # Step 1: Enforce security questions only
        if not self.is_security_question(query):
            return "SECURITY RESTRICTION: I am a specialized AI for cybersecurity. I can only answer questions related to security, attacks, bugs, and vulnerabilities."
            
        # Step 2: Retrieve context
        context = self.retrieve(query)
        
        if not context:
            return "I'm sorry, but I don't have enough information in my training data about this specific security topic."
            
        # Step 3: Formulate the prompt for the generative model
        prompt = (
            f"Context information: {context}\n\n"
            f"Based on the context provided, answer the following cybersecurity question clearly and concisely: {query}"
        )
        
        # Step 4: Generate answer
        result = self.generator(prompt, max_length=200, num_return_sequences=1)
        
        if result and len(result) > 0:
            return result[0]['generated_text']
        else:
            return "Failed to generate a response."

if __name__ == "__main__":
    # Example usage of the system
    rag = SecurityRAGSystem()
    
    test_queries = [
        "What is SQL Injection?",
        "Explain what a buffer overflow is.",
        "What is the recipe for chocolate cake?",
        "How does a path traversal attack work?"
    ]
    
    print("\n--- Running Security RAG Tests ---\n")
    for q in test_queries:
        print(f"User Question: {q}")
        print(f"AI Response:   {rag.generate_response(q)}\n")
        print("-" * 50)

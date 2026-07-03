"""
RAG Controller

Exposes the Security RAG system via REST API endpoints.
"""
from flask import Blueprint, request, jsonify
import logging

try:
    from app.services.rag_service import SecurityRAGService
except ImportError as e:
    logging.error(f"Could not import RAG service. Dependencies might be missing: {e}")
    SecurityRAGService = None

rag_bp = Blueprint('rag', __name__)
logger = logging.getLogger(__name__)

@rag_bp.route('/ask', methods=['POST'])
def ask_question():
    """
    Endpoint to ask the RAG AI a cybersecurity question.
    Expects JSON: { "question": "What is SQLi?" }
    """
    if not SecurityRAGService:
        return jsonify({
            "error": "RAG Service is currently unavailable due to missing dependencies.",
            "instructions": "Run: pip install transformers sentence-transformers torch"
        }), 503

    data = request.get_json()
    
    if not data or 'question' not in data:
        return jsonify({"error": "Missing 'question' in request body"}), 400
        
    question = data['question']
    
    try:
        # Get singleton instance (loads models on first use if not already loaded)
        rag_service = SecurityRAGService.get_instance()
        
        # Generate response
        answer = rag_service.generate_response(question)
        
        return jsonify({
            "question": question,
            "answer": answer
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating RAG response: {str(e)}")
        return jsonify({"error": "An internal error occurred while processing your request."}), 500

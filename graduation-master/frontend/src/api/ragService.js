import API from './client';

/**
 * Service to handle communication with the backend Security RAG MVC system.
 */
export const ragService = {
  /**
   * Send a question to the RAG AI.
   * @param {string} question 
   * @returns {Promise<string>} The AI's answer
   */
  askQuestion: async (question) => {
    try {
      const response = await API.post('/rag/ask', { question });
      return response.answer;
    } catch (error) {
      console.error("RAG API Error:", error);
      throw error;
    }
  }
};

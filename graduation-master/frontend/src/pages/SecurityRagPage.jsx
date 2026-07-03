import React, { useState, useRef, useEffect, useCallback } from 'react';
import { PaperAirplaneIcon, ShieldCheckIcon, CpuChipIcon } from '@heroicons/react/24/outline';
import { ragService } from '../api/ragService';
import { useAuth } from '../utils/useAuth';

export default function SecurityRagPage() {
  const { user } = useAuth();
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [messages, setMessages] = useState([
    {
      id: 1,
      text: `Hello ${user?.username || 'Analyst'}. I am the Virex Security RAG System. Ask me about vulnerabilities, attacks, or security concepts.`,
      sender: 'bot',
      timestamp: new Date(),
    },
  ]);

  const scrollRef = useRef(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userText = input;
    const userMsg = { id: Date.now(), text: userText, sender: 'user', timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    try {
      const answer = await ragService.askQuestion(userText);
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 1,
          text: answer || 'No response generated.',
          sender: 'bot',
          timestamp: new Date(),
        },
      ]);
    } catch (err) {
      console.error('RAG Error:', err);
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 1,
          text: 'Error connecting to the Security RAG service. Is the backend running?',
          sender: 'bot',
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-4rem)] w-full flex-col bg-bg-main overflow-hidden p-2 sm:p-6">
      {/* ── Main Chat Container ── */}
      <div className="flex flex-1 flex-col overflow-hidden rounded-xl border border-white/[0.08] bg-bg-secondary/40 shadow-chat-panel backdrop-blur-xl">
        
        {/* Header */}
        <header className="flex items-center justify-between border-b border-white/[0.08] bg-brand-primary/5 px-6 py-4 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-brand-primary/30 bg-brand-primary/20 text-brand-primary shadow-inner">
              <ShieldCheckIcon className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-ds-h4 font-bold text-text-primary">Virex RAG Analyst</h1>
              <p className="flex items-center gap-2 text-ds-body-sm text-text-muted">
                <span className="h-2 w-2 animate-pulse rounded-full bg-success"></span>
                Secure AI Knowledge Base Connected
              </p>
            </div>
          </div>
        </header>

        {/* Messages Area */}
        <div 
          ref={scrollRef}
          className="flex-1 overflow-y-auto p-4 sm:p-6 custom-scrollbar flex flex-col gap-6"
        >
          {messages.map((m) => (
            <div key={m.id} className={`flex w-full ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
              
              {m.sender === 'bot' && (
                <div className="mr-3 hidden h-10 w-10 shrink-0 items-center justify-center rounded-full border border-border-dim/50 bg-bg-card/80 text-brand-primary backdrop-blur-sm sm:flex">
                  <CpuChipIcon className="h-5 w-5" />
                </div>
              )}

              <div
                className={`max-w-[90%] sm:max-w-[75%] px-5 py-4 text-ds-body leading-relaxed ${
                  m.sender === 'user'
                    ? 'rounded-2xl rounded-br-md bg-brand-gradient text-white shadow-md shadow-brand-primary/20'
                    : 'rounded-2xl rounded-bl-md border border-white/[0.08] bg-white/[0.04] text-text-secondary shadow-sm backdrop-blur-md'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}

          {isTyping && (
            <div className="flex w-full justify-start">
              <div className="mr-3 hidden h-10 w-10 shrink-0 items-center justify-center rounded-full border border-border-dim/50 bg-bg-card/80 text-brand-primary backdrop-blur-sm sm:flex">
                <CpuChipIcon className="h-5 w-5" />
              </div>
              <div className="flex items-center gap-2 rounded-2xl rounded-bl-md border border-white/[0.08] bg-white/[0.04] px-5 py-4 shadow-sm backdrop-blur-md">
                <span className="h-2.5 w-2.5 rounded-full bg-brand-primary/80 animate-bounce"></span>
                <span className="h-2.5 w-2.5 rounded-full bg-brand-primary/80 animate-bounce delay-100"></span>
                <span className="h-2.5 w-2.5 rounded-full bg-brand-primary/80 animate-bounce delay-200"></span>
              </div>
            </div>
          )}
        </div>

        {/* Input Area */}
        <div className="border-t border-white/[0.08] bg-bg-main/40 p-4 backdrop-blur-md sm:p-6">
          <form onSubmit={handleSend} className="relative mx-auto flex w-full max-w-4xl items-end gap-3">
            <div className="relative flex-1">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend(e);
                  }
                }}
                placeholder="Ask about vulnerabilities (e.g. 'What is SQL Injection?')"
                rows={1}
                className="max-h-32 min-h-[3.5rem] w-full resize-none rounded-xl border border-white/[0.1] bg-bg-card/50 pl-4 pr-12 pt-3.5 text-ds-body text-text-primary placeholder:text-text-muted shadow-inner backdrop-blur-sm transition-all focus:border-brand-primary focus:outline-none focus:ring-1 focus:ring-brand-primary"
              />
            </div>
            <button
              type="submit"
              disabled={!input.trim() || isTyping}
              className="flex h-[3.5rem] w-[3.5rem] shrink-0 items-center justify-center rounded-xl bg-brand-gradient text-white shadow-md transition-all hover:scale-105 disabled:cursor-not-allowed disabled:opacity-40 motion-safe:active:scale-95"
            >
              <PaperAirplaneIcon className="h-6 w-6 -rotate-12" />
            </button>
          </form>
          <div className="mt-3 text-center text-ds-micro text-text-muted">
            The RAG Analyst is trained exclusively on security context and vulnerabilities. Responses are strictly limited to cybersecurity domains.
          </div>
        </div>
      </div>
    </div>
  );
}

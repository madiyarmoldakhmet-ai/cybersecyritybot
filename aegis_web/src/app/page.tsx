'use client';

import { useState, useEffect, useRef, FormEvent } from 'react';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import { motion, AnimatePresence } from 'framer-motion';

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
};

export default function Home() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    { id: '1', role: 'assistant', content: 'Hello. I am Aegis, your AI thinking partner for security. Paste a GitHub repository link to begin a deep agentic audit, or ask me about vulnerability patterns.' }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  
  // Scanner state
  const [isScanning, setIsScanning] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [scannedFiles, setScannedFiles] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [vulnerabilities, setVulnerabilities] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);

  const chatWsRef = useRef<WebSocket | null>(null);
  const scanWsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Initialize Chat WebSocket
  useEffect(() => {
    const wsUrl = process.env.NEXT_PUBLIC_CHAT_WS_URL || "ws://localhost:8000/ws/chat";
    const ws = new WebSocket(wsUrl);
    chatWsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'action' && data.action === 'SCAN') {
        startScan(data.github_url);
      } else if (data.type === 'chunk') {
        setIsTyping(false);
        setMessages(prev => {
          const last = prev[prev.length - 1];
          if (last && last.role === 'assistant' && last.id === 'streaming') {
            return [...prev.slice(0, -1), { ...last, content: last.content + data.content }];
          } else {
            return [...prev, { id: 'streaming', role: 'assistant', content: data.content }];
          }
        });
      } else if (data.type === 'done') {
        setMessages(prev => {
          const last = prev[prev.length - 1];
          if (last && last.id === 'streaming') {
            return [...prev.slice(0, -1), { ...last, id: Date.now().toString() }];
          }
          return prev;
        });
      }
    };

    return () => {
      ws.close();
      if (scanWsRef.current) scanWsRef.current.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Auto-scroll chat
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !chatWsRef.current) return;

    const userMsg = input.trim();
    setMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', content: userMsg }]);
    setInput('');
    setIsTyping(true);
    
    // Create a temporary streaming message block
    setMessages(prev => [...prev, { id: 'streaming', role: 'assistant', content: '' }]);

    chatWsRef.current.send(userMsg);
  };

  const startScan = (repoUrl: string) => {
    // Reset scanner state
    setEvents([]);
    setScannedFiles(0);
    setTotalFiles(0);
    setVulnerabilities(0);
    setElapsedTime(0);
    setIsScanning(true);

    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setElapsedTime(prev => prev + 1);
    }, 1000);

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/scan";
    const ws = new WebSocket(wsUrl);
    scanWsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ github_url: repoUrl }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [...prev, data]);

      if (data.event_type === 'ScanStarted' && data.total_files) {
        setTotalFiles(data.total_files);
      } else if (data.event_type === 'FileScanning') {
        setScannedFiles(prev => prev + 1);
      } else if (data.event_type === 'VulnerabilityFound') {
        setVulnerabilities(prev => prev + 1);
      } else if (data.event_type === 'ScanCompleted' || data.event_type === 'SystemError') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };
  };

  return (
    <div className="min-h-screen bg-[var(--color-canvas)] text-[var(--color-ink)] font-sans flex flex-col">
      {/* Top Nav */}
      <header className="h-16 border-b border-[#e8e0d2] flex items-center justify-between px-6 shrink-0 bg-[var(--color-canvas)]">
        <div className="flex items-center gap-2">
          {/* Anthropic/Aegis Spike Mark */}
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L12 22M2 12L22 12M5 5L19 19M19 5L5 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <span className="font-serif text-xl tracking-tight">Aegis</span>
        </div>
        <div className="flex items-center gap-6 text-sm font-medium">
          <a href="#" className="hover:text-[var(--color-primary)] transition-colors">Product</a>
          <a href="#" className="hover:text-[var(--color-primary)] transition-colors">Research</a>
          <a href="#" className="hover:text-[var(--color-primary)] transition-colors">Pricing</a>
          <button className="text-[var(--color-ink)] hover:text-[var(--color-primary)] transition-colors">Sign in</button>
          <button className="bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] text-white px-5 py-2.5 rounded-md transition-colors font-medium">
            Try Aegis
          </button>
        </div>
      </header>

      {/* Main Content Split */}
      <main className="flex-1 flex flex-col lg:flex-row max-w-[1440px] mx-auto w-full p-8 gap-12">
        
        {/* Left Side: Editorial Intro & Chat */}
        <div className="flex-1 flex flex-col max-w-2xl">
          <div className="mb-12 mt-8">
            <h1 className="font-serif text-5xl lg:text-[64px] leading-[1.05] tracking-[-1.5px] mb-6">
              Meet your thinking partner for security.
            </h1>
            <p className="text-lg text-[#3d3d3a] leading-relaxed">
              Aegis performs deep agentic security audits, analyzing codebases for semantic vulnerabilities, hardcoded secrets, and architectural flaws in real time. 
            </p>
          </div>

          {/* Chat Interface */}
          <div className="flex-1 flex flex-col bg-[#efe9de] rounded-xl overflow-hidden min-h-[400px]">
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] rounded-lg p-4 leading-relaxed ${
                    msg.role === 'user' 
                      ? 'bg-[var(--color-primary)] text-white' 
                      : 'bg-white border border-[#e8e0d2] text-[var(--color-ink)] shadow-sm'
                  }`}>
                    {msg.content}
                    {msg.role === 'assistant' && msg.id === 'streaming' && (
                      <span className="inline-block w-1.5 h-4 ml-1 bg-[var(--color-primary)] animate-pulse" />
                    )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
            
            <div className="p-4 bg-white border-t border-[#e8e0d2]">
              <form onSubmit={handleSendMessage} className="relative">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask a question or paste a GitHub URL to scan..."
                  className="w-full bg-[var(--color-canvas)] border border-[#e6dfd8] rounded-md px-4 py-3 pr-12 focus:outline-none focus:border-[var(--color-primary)] transition-colors placeholder:text-[#8e8b82]"
                />
                <button 
                  type="submit"
                  disabled={!input.trim()}
                  className="absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] text-white rounded-md disabled:opacity-50 transition-colors"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Right Side: Product Mockup Surface */}
        <div className="flex-1 mt-8">
          <div className="bg-[var(--color-surface-dark)] rounded-xl p-8 h-full min-h-[600px] flex flex-col shadow-xl">
            <div className="mb-6">
              <h2 className="text-[var(--color-on-dark)] font-serif text-2xl tracking-tight">Terminal Output</h2>
              <p className="text-[#a09d96] text-sm mt-1 font-mono">Live execution environment</p>
            </div>
            
            <MetricsDashboard
              scannedFiles={scannedFiles}
              totalFiles={totalFiles}
              vulnerabilities={vulnerabilities}
              elapsedTime={elapsedTime}
            />
            
            <div className="flex-1 mt-6 bg-[#1f1e1b] rounded-lg overflow-hidden border border-[#252320]">
              <TerminalWindow events={events} className="h-full" />
            </div>
          </div>
        </div>

      </main>
    </div>
  );
}

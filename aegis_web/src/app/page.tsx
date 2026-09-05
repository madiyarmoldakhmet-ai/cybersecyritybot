'use client';

import { useState, useEffect, useRef, FormEvent } from 'react';
import { ThemeToggle } from '@/components/ThemeToggle';
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
    { id: '1', role: 'assistant', content: 'Aegis — сканер уязвимостей. Отправьте ZIP-архив с кодом или ссылку на репозиторий.' }
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

  useEffect(() => {
    const connectChatWs = () => {
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
        } else if (data.type === 'error') {
            setIsTyping(false);
            setMessages(prev => [...prev.filter(m => m.id !== 'streaming'), { id: Date.now().toString(), role: 'assistant', content: `Ошибка: ${data.message}` }]);
        }
      };

      ws.onclose = () => {
        setMessages(prev => [...prev, { id: Date.now().toString(), role: 'assistant', content: 'Соединение потеряно. Переподключение...' }]);
        setTimeout(connectChatWs, 2000); // retry after 2 seconds
      };
    };

    connectChatWs();

    return () => {
      if (chatWsRef.current) chatWsRef.current.onclose = null;
      chatWsRef.current?.close();
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

  const handleZipUpload = async (file: File) => {
    if (!file.name.endsWith('.zip')) {
      setMessages(prev => [...prev, { id: Date.now().toString(), role: 'assistant', content: 'Пожалуйста, загрузите ZIP-архив.' }]);
      return;
    }

    setMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', content: `[Загружен файл: ${file.name}]` }]);
    setMessages(prev => [...prev, { id: 'streaming', role: 'assistant', content: 'Загрузка архива и начало сканирования...' }]);
    
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch((process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000') + '/api/scan/upload', {
        method: 'POST',
        body: formData,
      });
      
      const data = await res.json();
      setMessages(prev => {
        const filtered = prev.filter(m => m.id !== 'streaming');
        if (res.ok) {
          return [...filtered, { id: Date.now().toString(), role: 'assistant', content: `Сканирование завершено. Найдено уязвимостей: ${data.vulnerabilities?.length || 0}.` }];
        } else {
          return [...filtered, { id: Date.now().toString(), role: 'assistant', content: `Ошибка при сканировании: ${data.error || 'Неизвестная ошибка'}` }];
        }
      });
    } catch (err) {
      setMessages(prev => [
        ...prev.filter(m => m.id !== 'streaming'),
        { id: Date.now().toString(), role: 'assistant', content: `Ошибка сети при загрузке: ${err}` }
      ]);
    }
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
      <header className="h-16 border-b border-[var(--color-surface-cream-strong)] flex items-center justify-between px-6 shrink-0 bg-[var(--color-canvas)]">
        <div className="flex items-center gap-2">
          {/* Anthropic/Aegis Spike Mark */}
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L12 22M2 12L22 12M5 5L19 19M19 5L5 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <span className="font-serif text-xl tracking-tight">Aegis</span>
        </div>
        <div className="flex items-center gap-6 text-sm font-medium">
          <ThemeToggle />
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
              Aegis Security Scanner
            </h1>
            <p className="text-lg text-[var(--color-body-text)] leading-relaxed">
              Сканер уязвимостей исходного кода. Поддерживает SAST, SCA и поиск секретов.
            </p>
          </div>

          {/* Chat Interface */}
          <div className="flex-1 flex flex-col bg-[var(--color-surface-card)] rounded-xl overflow-hidden min-h-[400px]">
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] rounded-lg p-4 leading-relaxed ${
                    msg.role === 'user' 
                      ? 'bg-[var(--color-primary)] text-white' 
                      : 'bg-[var(--color-surface-input)] border border-[var(--color-surface-cream-strong)] text-[var(--color-ink)] shadow-sm'
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
            
            <div className="p-4 bg-[var(--color-surface-input)] border-t border-[var(--color-surface-cream-strong)]">
              <form onSubmit={handleSendMessage} className="relative mb-4">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Отправьте ссылку на GitHub..."
                  className="w-full bg-[var(--color-canvas)] border border-[var(--color-surface-cream-strong)] rounded-md px-4 py-3 pr-12 focus:outline-none focus:border-[var(--color-primary)] transition-colors placeholder:text-[var(--color-muted-soft)]"
                />
                <button 
                  type="submit"
                  disabled={!input.trim()}
                  className="absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] text-white rounded-md disabled:opacity-50 transition-colors"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
                </button>
              </form>
              <div 
                className="w-full border-2 border-dashed border-[var(--color-surface-cream-strong)] rounded-lg p-6 flex items-center justify-center cursor-pointer hover:border-[var(--color-primary)] transition-colors bg-[var(--color-canvas)]"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleZipUpload(e.dataTransfer.files[0]);
                  }
                }}
                onClick={() => document.getElementById('zip-upload')?.click()}
              >
                <input 
                  type="file" 
                  id="zip-upload" 
                  accept=".zip" 
                  className="hidden" 
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) handleZipUpload(e.target.files[0]);
                  }}
                />
                <p className="text-[var(--color-muted-soft)] text-sm font-medium">Перетащите ZIP-архив. Код не сохраняется на сервере.</p>
              </div>
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

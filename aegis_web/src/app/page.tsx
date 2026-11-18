'use client';

import { useState, useEffect, useRef, FormEvent } from 'react';
import Link from 'next/link';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import { SecurityScore } from '@/components/SecurityScore';
import { ShieldCheck, Play, FileText, Wrench, Upload, Sparkles, X } from 'lucide-react';

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
};

type Finding = {
  id: string;
  scanner: string;
  title: string;
  description: string;
  severity: string;
  file_path: string;
  line_start?: number | null;
  line_end?: number | null;
  code_snippet?: string | null;
  cwe: string[];
  cve: string[];
  recommendation?: string | null;
};

type RemediationResult = {
  finding_id: string;
  vuln_name: string;
  severity: string;
  explanation_ru: string;
  impact_analysis: string;
  remediation_steps: string[];
  fixed_code: string;
  diff_patch?: string | null;
  confidence_score: number;
};

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-300 border border-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-300 border border-orange-500/40',
  MEDIUM: 'bg-amber-500/20 text-amber-300 border border-amber-500/40',
  LOW: 'bg-blue-500/20 text-blue-300 border border-blue-500/40',
  INFO: 'bg-slate-500/20 text-slate-300 border border-slate-500/40',
};

export default function Home() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      role: 'assistant',
      content:
        'Commit Guardian готов к работе. Нажмите «Демо-аудит» для мгновенной проверки финтех-сервиса, перетащите ZIP или отправьте ссылку на GitHub.',
    },
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  // Scan & audit state
  const [isScanning, setIsScanning] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scannedFiles, setScannedFiles] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [vulnerabilities, setVulnerabilities] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [securityScore, setSecurityScore] = useState<number | null>(null);
  const [grade, setGrade] = useState<string | null>(null);
  const [auditSummary, setAuditSummary] = useState<string>('');
  const [reportPdfUrl, setReportPdfUrl] = useState<string | null>(null);
  const [reportMdUrl, setReportMdUrl] = useState<string | null>(null);
  const [activeTarget, setActiveTarget] = useState<string>('');

  // Native <dialog> refs
  const pricingDialogRef = useRef<HTMLDialogElement>(null);
  const fixDialogRef = useRef<HTMLDialogElement>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [remediation, setRemediation] = useState<RemediationResult | null>(null);
  const [isFixing, setIsFixing] = useState(false);

  const chatWsRef = useRef<WebSocket | null>(null);
  const scanWsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const startScanRef = useRef<(repoUrl: string) => void>(() => {});

  useEffect(() => {
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let unmounted = false;

    const connectChatWs = () => {
      if (typeof window === 'undefined' || unmounted) return;
      const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/chat`;
      const ws = new WebSocket(wsUrl);
      chatWsRef.current = ws;

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'action' && data.action === 'SCAN') {
          startScanRef.current(data.github_url);
        } else if (data.type === 'chunk') {
          setIsTyping(false);
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.role === 'assistant' && last.id === 'streaming') {
              return [...prev.slice(0, -1), { ...last, content: last.content + data.content }];
            }
            return [...prev, { id: 'streaming', role: 'assistant', content: data.content }];
          });
        } else if (data.type === 'done') {
          setIsTyping(false);
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.id === 'streaming') {
              return [...prev.slice(0, -1), { ...last, id: Date.now().toString() }];
            }
            return prev;
          });
        } else if (data.type === 'error') {
          setIsTyping(false);
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            { id: Date.now().toString(), role: 'assistant', content: `Ошибка: ${data.message}` },
          ]);
        }
      };

      ws.onclose = () => {
        if (!unmounted) {
          reconnectTimer = setTimeout(connectChatWs, 3000);
        }
      };
    };

    connectChatWs();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (chatWsRef.current) chatWsRef.current.onclose = null;
      chatWsRef.current?.close();
      scanWsRef.current?.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const resetScanState = (targetLabel: string) => {
    setEvents([]);
    setFindings([]);
    setScannedFiles(0);
    setTotalFiles(0);
    setVulnerabilities(0);
    setElapsedTime(0);
    setSecurityScore(null);
    setGrade(null);
    setAuditSummary('');
    setReportPdfUrl(null);
    setReportMdUrl(null);
    setActiveTarget(targetLabel);
    setIsScanning(true);

    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setElapsedTime((prev) => +(prev + 0.2).toFixed(1));
    }, 200);
  };

  const applyCompletedPayload = (data: {
    repo_name?: string;
    total_findings?: number;
    vulnerabilities?: Finding[];
    findings?: Finding[];
    security_score?: number;
    grade?: string;
    summary?: string;
    report_pdf_url?: string | null;
    report_md_url?: string | null;
    scan_result?: { duration_seconds?: number };
    duration_seconds?: number;
  }) => {
    const list = data.vulnerabilities || data.findings || [];
    setFindings(list);
    setVulnerabilities(data.total_findings ?? list.length);
    if (typeof data.security_score === 'number') setSecurityScore(data.security_score);
    if (data.grade) setGrade(data.grade);
    if (data.summary) setAuditSummary(data.summary);
    setReportPdfUrl(data.report_pdf_url ?? null);
    setReportMdUrl(data.report_md_url ?? null);
    if (typeof data.scan_result?.duration_seconds === 'number') {
      setElapsedTime(data.scan_result.duration_seconds);
    } else if (typeof data.duration_seconds === 'number') {
      setElapsedTime(data.duration_seconds);
    }
    setIsScanning(false);
    if (timerRef.current) clearInterval(timerRef.current);

    setEvents((prev) => [
      ...prev,
      ...list.slice(0, 6).map((f) => ({
        event_type: 'VulnerabilityFound' as const,
        severity: f.severity,
        title: f.title,
        file_path: `${f.file_path}:${f.line_start || 1}`,
        message: f.description,
      })),
      {
        event_type: 'ScanCompleted' as const,
        total_findings: list.length,
        message: `Аудит ${data.repo_name || ''} завершён · Score ${data.security_score ?? '-'}/100 (${data.grade ?? '-'})`,
      },
    ]);
  };

  const handleSendMessage = (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = input.trim();
    setMessages((prev) => [...prev, { id: Date.now().toString(), role: 'user', content: userMsg }]);
    setInput('');

    if (!chatWsRef.current || chatWsRef.current.readyState !== WebSocket.OPEN) {
      if (userMsg.includes('github.com/')) {
        const match = userMsg.split(/\s+/).find((w) => w.includes('github.com/'));
        if (match) startScan(match);
        return;
      }
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          role: 'assistant',
          content: 'Отправьте ссылку на GitHub (например, https://github.com/owner/repo), загрузите ZIP или нажмите «Демо-аудит».',
        },
      ]);
      return;
    }

    setIsTyping(true);
    setMessages((prev) => [...prev, { id: 'streaming', role: 'assistant', content: '' }]);
    chatWsRef.current.send(userMsg);
  };

  const handleDemoScan = async () => {
    resetScanState('demo/kz-fintech-app');
    setMessages((prev) => [
      ...prev,
      { id: Date.now().toString(), role: 'user', content: '[Демо-аудит встроенного KZ Fintech сервиса]' },
      { id: 'streaming', role: 'assistant', content: 'Запускаю локальный аудит демо-сервиса (SAST + Taint + Secrets + .aegis.yml)...' },
    ]);
    setEvents([{ event_type: 'ScanStarted', message: 'Инициализация on-premise движка Commit Guardian...' }]);

    try {
      const res = await fetch('/api/scan/demo', { method: 'POST' });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'streaming');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: Date.now().toString(),
              role: 'assistant',
              content: `Демо-аудит завершён: найдено ${data.total_findings} уязвимостей, Security Score: ${data.security_score}/100 (${data.grade}).`,
            },
          ];
        }
        return [...filtered, { id: Date.now().toString(), role: 'assistant', content: `Ошибка демо-скана: ${data.error}` }];
      });
      if (res.ok) {
        setScannedFiles(2);
        setTotalFiles(2);
        applyCompletedPayload(data);
      } else {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    } catch (err) {
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'streaming'),
        { id: Date.now().toString(), role: 'assistant', content: `Ошибка сети при демо-скане: ${err}` },
      ]);
    }
  };

  const handleZipUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setMessages((prev) => [...prev, { id: Date.now().toString(), role: 'assistant', content: 'Пожалуйста, загрузите ZIP-архив.' }]);
      return;
    }

    resetScanState(`upload/${file.name}`);
    setMessages((prev) => [
      ...prev,
      { id: Date.now().toString(), role: 'user', content: `[Загружен архив: ${file.name}]` },
      { id: 'streaming', role: 'assistant', content: 'Распаковка в изолированную папку и локальный анализ...' },
    ]);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/scan/upload', { method: 'POST', body: formData });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'streaming');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: Date.now().toString(),
              role: 'assistant',
              content: `Аудит завершён: найдено ${data.total_findings ?? 0} уязвимостей · Score ${data.security_score ?? '-'}/100 (${data.grade ?? '-'}). Исходный код удалён с сервера.`,
            },
          ];
        }
        return [
          ...filtered,
          { id: Date.now().toString(), role: 'assistant', content: `Ошибка при сканировании: ${data.error || 'Неизвестная ошибка'}` },
        ];
      });
      if (res.ok) {
        applyCompletedPayload(data);
      } else {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    } catch (err) {
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'streaming'),
        { id: Date.now().toString(), role: 'assistant', content: `Ошибка сети при загрузке: ${err}` },
      ]);
    }
  };

  const startScan = (repoUrl: string) => {
    resetScanState(repoUrl);
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/scan`;
    const ws = new WebSocket(wsUrl);
    scanWsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ github_url: repoUrl }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.event_type === 'ScanResult') {
        applyCompletedPayload(data);
        return;
      }
      setEvents((prev) => [...prev, data]);
      if (data.event_type === 'ScanStarted' && data.total_files) {
        setTotalFiles(data.total_files);
      } else if (data.event_type === 'FileScanning') {
        setScannedFiles((prev) => prev + 1);
      } else if (data.event_type === 'VulnerabilityFound') {
        setVulnerabilities((prev) => prev + 1);
      } else if (data.event_type === 'ScanCompleted' || data.event_type === 'SystemError') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };
  };

  useEffect(() => {
    startScanRef.current = startScan;
  });

  const handleOpenRemediation = async (finding: Finding) => {
    setSelectedFinding(finding);
    setRemediation(null);
    setIsFixing(true);
    fixDialogRef.current?.showModal();

    try {
      const res = await fetch('/api/v1/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, code_context: finding.code_snippet || '' }),
      });
      if (res.ok) {
        setRemediation(await res.json());
      }
    } catch {
      // Fallback UI handles null remediation cleanly
    } finally {
      setIsFixing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-canvas)] text-[var(--color-ink)] font-sans flex flex-col">
      {/* Semantic Navigation Header (navbar guide: single nav landmark + aria-current) */}
      <header className="site-header h-16 border-b border-[var(--color-surface-cream-strong)] px-6 shrink-0 bg-[var(--color-canvas)]">
        <div className="max-w-[1440px] mx-auto h-full flex items-center justify-between gap-4">
          <Link href="/" className="flex items-center gap-2.5 text-[var(--color-ink)] no-underline shrink-0">
            <ShieldCheck className="w-6 h-6 text-[var(--color-primary)]" aria-hidden="true" />
            <span className="font-serif text-xl tracking-tight font-semibold">Commit Guardian</span>
          </Link>

          <nav aria-label="Основная навигация" className="flex items-center gap-5 text-sm font-medium">
            <Link href="/" aria-current="page" className="nav-link hover:text-[var(--color-primary)] transition-colors">
              Консоль
            </Link>
            <a href="/dashboard" className="nav-link hover:text-[var(--color-primary)] transition-colors">
              Мониторинг
            </a>
            <button
              type="button"
              onClick={() => pricingDialogRef.current?.showModal()}
              className="hover:text-[var(--color-primary)] transition-colors cursor-pointer"
            >
              On-Premise &amp; Тарифы
            </button>
            <ThemeToggle />
            <button
              type="button"
              onClick={handleDemoScan}
              disabled={isScanning}
              className="bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] disabled:opacity-60 text-white px-4 py-2 rounded-md transition-colors font-medium inline-flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Демо-аудит</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Split */}
      <main className="flex-1 flex flex-col lg:flex-row max-w-[1440px] mx-auto w-full p-6 lg:p-8 gap-8">
        {/* Left Side: Startup Positioning, 1-Click Demo & Chat/Upload */}
        <section className="flex-1 flex flex-col max-w-2xl" aria-label="Управление аудитом">
          <div className="mb-6">
            <div className="inline-flex items-center gap-2 text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded-full bg-[var(--color-surface-card)] border border-[var(--color-surface-cream-strong)] text-[var(--color-body-text)] mb-3">
              <span>100% On-Premise · Air-Gapped AI</span>
            </div>
            <h1 className="font-serif text-4xl lg:text-5xl leading-[1.08] tracking-tight mb-3">
              Commit Guardian
            </h1>
            <p className="text-base text-[var(--color-body-text)] leading-relaxed">
              Локальный AppSec-аудитор каждого коммита для банков, финтеха и GovTech: SAST, межфайловый Taint-анализ,
              поиск утечек ИИН/секретов и официальный PDF-отчёт без отправки кода в облако.
            </p>
            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={handleDemoScan}
                disabled={isScanning}
                className="bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] disabled:opacity-60 text-white px-4 py-2.5 rounded-lg text-sm font-medium inline-flex items-center gap-2 transition-colors cursor-pointer"
              >
                <Sparkles className="w-4 h-4" aria-hidden="true" />
                <span>Запустить демо-аудит (KZ Fintech)</span>
              </button>
              <a
                href="/dashboard"
                className="px-4 py-2.5 rounded-lg text-sm font-medium border border-[var(--color-surface-cream-strong)] bg-[var(--color-surface-card)] hover:border-[var(--color-primary)] transition-colors inline-flex items-center gap-2"
              >
                <FileText className="w-4 h-4" aria-hidden="true" />
                <span>Журнал аудитов (/dashboard)</span>
              </a>
            </div>
          </div>

          {/* Interactive Chat & Upload Box */}
          <div className="flex-1 flex flex-col bg-[var(--color-surface-card)] border border-[var(--color-surface-cream-strong)] rounded-xl overflow-hidden min-h-[360px]">
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[85%] rounded-lg p-3.5 text-sm leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-[var(--color-primary)] text-white'
                        : 'bg-[var(--color-surface-input)] border border-[var(--color-surface-cream-strong)] text-[var(--color-ink)] shadow-sm'
                    }`}
                  >
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
              <form onSubmit={handleSendMessage} className="relative mb-3">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ссылка на GitHub (https://github.com/owner/repo) или вопрос..."
                  aria-label="Ссылка на репозиторий GitHub или сообщение"
                  className="w-full bg-[var(--color-canvas)] border border-[var(--color-surface-cream-strong)] rounded-md px-4 py-2.5 pr-12 text-sm focus:outline-none focus:border-[var(--color-primary)] transition-colors placeholder:text-[var(--color-muted-soft)]"
                />
                <button
                  type="submit"
                  disabled={!input.trim() || isTyping}
                  aria-label="Отправить"
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] text-white rounded-md disabled:opacity-50 transition-colors cursor-pointer"
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                  </svg>
                </button>
              </form>
              <button
                type="button"
                className="w-full border-2 border-dashed border-[var(--color-surface-cream-strong)] rounded-lg p-4 flex items-center justify-center gap-2 cursor-pointer hover:border-[var(--color-primary)] transition-colors bg-[var(--color-canvas)]"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleZipUpload(e.dataTransfer.files[0]);
                  }
                }}
                onClick={() => document.getElementById('zip-upload')?.click()}
              >
                <Upload className="w-4 h-4 text-[var(--color-muted-soft)]" aria-hidden="true" />
                <input
                  type="file"
                  id="zip-upload"
                  accept=".zip"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) handleZipUpload(e.target.files[0]);
                  }}
                />
                <span className="text-[var(--color-muted-soft)] text-xs font-medium">
                  Загрузите или перетащите ZIP-архив (исходники удаляются сразу после проверки)
                </span>
              </button>
            </div>
          </div>
        </section>

        {/* Right Side: Live Execution Console, Security Score & Compliance Findings */}
        <section className="flex-1 min-w-0" aria-label="Консоль результатов аудита">
          <div className="bg-[var(--color-surface-dark)] rounded-xl p-6 h-full flex flex-col gap-5 shadow-xl text-[#faf9f5]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-[var(--color-on-dark)] font-serif text-2xl tracking-tight">Консоль аудита</h2>
                <p className="text-[#a09d96] text-xs mt-0.5 font-mono">
                  {activeTarget ? `Цель: ${activeTarget}` : 'Локальное окружение готово к сканированию'}
                </p>
              </div>
              {reportPdfUrl && (
                <div className="flex items-center gap-2">
                  <a
                    href={reportPdfUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-md bg-[var(--color-primary)] hover:bg-[var(--color-primary-active)] text-white text-xs font-mono inline-flex items-center gap-1.5"
                  >
                    <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                    Скачать PDF
                  </a>
                  {reportMdUrl && (
                    <a
                      href={reportMdUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 rounded-md border border-[#3a3733] hover:border-[var(--color-primary)] text-[#faf9f5] text-xs font-mono"
                    >
                      MD
                    </a>
                  )}
                </div>
              )}
            </div>

            <MetricsDashboard
              scannedFiles={scannedFiles}
              totalFiles={totalFiles}
              vulnerabilities={vulnerabilities}
              elapsedTime={elapsedTime}
              securityScore={securityScore}
              grade={grade}
              isScanning={isScanning}
            />

            {securityScore !== null && (
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <SecurityScore score={securityScore} grade={grade ?? undefined} />
                {auditSummary && (
                  <div className="bg-[#1f1e1b] border border-[#2b2926] rounded-xl p-4 flex flex-col justify-between">
                    <div className="text-xs font-mono uppercase tracking-wider text-[#a09d96] mb-1.5">
                      Заключение аудитора
                    </div>
                    <p className="text-xs text-[#e5e2dc] leading-relaxed">{auditSummary}</p>
                  </div>
                )}
              </div>
            )}

            {findings.length > 0 ? (
              <div
                tabIndex={0}
                role="region"
                aria-labelledby="findings-caption"
                className="table-wrapper bg-[#1f1e1b] border border-[#2b2926] rounded-xl"
              >
                <table className="findings-table text-left text-xs">
                  <caption id="findings-caption" className="sr-only">
                    Обнаруженные уязвимости исходного кода
                  </caption>
                  <thead>
                    <tr className="text-[#a09d96] border-b border-[#2b2926]">
                      <th className="p-3 font-medium">Уровень</th>
                      <th className="p-3 font-medium">Уязвимость и файл</th>
                      <th className="p-3 font-medium">CWE</th>
                      <th className="p-3 font-medium text-right">Патч</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2b2926]">
                    {findings.map((f, idx) => (
                      <tr key={`${f.id}-${idx}`} className="hover:bg-[#252320]/70 transition-colors">
                        <td data-label="Уровень" className="p-3 whitespace-nowrap align-top">
                          <span className={`px-2 py-0.5 rounded font-mono text-[11px] ${SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO}`}>
                            {f.severity}
                          </span>
                        </td>
                        <th scope="row" className="p-3 font-normal align-top">
                          <div className="font-semibold text-[#faf9f5]">{f.title}</div>
                          <div className="font-mono text-[11px] text-[#a09d96] mt-0.5">
                            {f.file_path}:{f.line_start || 1} · {f.scanner}
                          </div>
                        </th>
                        <td data-label="CWE" className="p-3 font-mono text-[#a09d96] whitespace-nowrap align-top">
                          {f.cwe?.join(', ') || '—'}
                        </td>
                        <td data-label="Патч" className="p-3 text-right whitespace-nowrap align-top">
                          <button
                            type="button"
                            onClick={() => handleOpenRemediation(f)}
                            className="px-2.5 py-1 rounded bg-[#2b2926] hover:bg-[var(--color-primary)] text-[#faf9f5] text-[11px] font-mono inline-flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <Wrench className="w-3 h-3" aria-hidden="true" />
                            <span>Исправить</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex-1 min-h-[260px] bg-[#1f1e1b] rounded-lg overflow-hidden border border-[#252320]">
                <TerminalWindow events={events} className="h-full" />
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Native <dialog>: AI Remediation & Diff Modal (per dialog guide: no role="dialog" / aria-modal) */}
      <dialog
        ref={fixDialogRef}
        aria-labelledby="remediation-dialog-title"
        className="m-auto w-[min(92vw,720px)] rounded-xl border border-[#2b2926] bg-[#181715] text-[#faf9f5] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <h2 id="remediation-dialog-title" className="font-serif text-2xl">
              {selectedFinding?.title || 'Патч безопасности'}
            </h2>
            {selectedFinding && (
              <p className="text-xs font-mono text-[#a09d96] mt-1">
                {selectedFinding.file_path}:{selectedFinding.line_start || 1} · {selectedFinding.cwe?.join(', ') || 'SAST'}
              </p>
            )}
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть окно патча"
              className="p-1.5 rounded hover:bg-[#2b2926] text-[#a09d96] hover:text-white cursor-pointer"
            >
              <X className="w-5 h-5" aria-hidden="true" />
            </button>
          </form>
        </div>

        {isFixing ? (
          <div className="py-8 text-sm font-mono text-[#a09d96]">Генерирую безопасный патч локальным движком...</div>
        ) : remediation ? (
          <div className="space-y-4 text-sm">
            <div>
              <div className="text-xs font-mono uppercase text-[#a09d96] mb-1">Причина и риск</div>
              <p className="text-[#e5e2dc] leading-relaxed">{remediation.explanation_ru}</p>
              <p className="text-amber-300/90 text-xs mt-1">{remediation.impact_analysis}</p>
            </div>
            {remediation.remediation_steps.length > 0 && (
              <div>
                <div className="text-xs font-mono uppercase text-[#a09d96] mb-1">Как устранить</div>
                <ul className="list-disc pl-5 space-y-1 text-xs text-[#e5e2dc]">
                  {remediation.remediation_steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
            <div>
              <div className="text-xs font-mono uppercase text-[#a09d96] mb-1">Безопасный код</div>
              <pre className="p-3 rounded-lg bg-[#0f0e0d] border border-[#2b2926] font-mono text-xs overflow-x-auto text-emerald-300">
                {remediation.fixed_code}
              </pre>
            </div>
          </div>
        ) : (
          <p className="text-sm text-[#a09d96]">
            {selectedFinding?.recommendation || selectedFinding?.description || 'Не удалось получить патч.'}
          </p>
        )}
      </dialog>

      {/* Native <dialog>: On-Premise Architecture & KZ B2B Pricing */}
      <dialog
        ref={pricingDialogRef}
        aria-labelledby="pricing-dialog-title"
        className="m-auto w-[min(92vw,760px)] rounded-xl border border-[#2b2926] bg-[#181715] text-[#faf9f5] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-5">
          <div>
            <h2 id="pricing-dialog-title" className="font-serif text-2xl">
              On-Premise архитектура и тарифы B2B
            </h2>
            <p className="text-xs text-[#a09d96] mt-1">
              Модель B2B-подписки внутри закрытого контура компании: исходный код и ПДн не покидают серверы заказчика.
            </p>
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть тарифы"
              className="p-1.5 rounded hover:bg-[#2b2926] text-[#a09d96] hover:text-white cursor-pointer"
            >
              <X className="w-5 h-5" aria-hidden="true" />
            </button>
          </form>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="rounded-lg border border-[#2b2926] bg-[#1f1e1b] p-4">
            <div className="font-mono text-xs text-emerald-400">PILOT</div>
            <div className="text-xl font-bold mt-1">0 ₸ / 14 дней</div>
            <p className="text-xs text-[#a09d96] mt-2">
              1–2 репозитория, Docker-развёртывание, алерты в Telegram и Compliance PDF для команды до 5 разработчиков.
            </p>
          </div>
          <div className="rounded-lg border border-[var(--color-primary)] bg-[#1f1e1b] p-4">
            <div className="font-mono text-xs text-[var(--color-primary)]">TEAM ON-PREM</div>
            <div className="text-xl font-bold mt-1">190 000 ₸ / мес</div>
            <p className="text-xs text-[#a09d96] mt-2">
              До 25 разработчиков, локальная Ollama, политики .aegis.yml (ИИН/ПДн), авто-комментарии в PR и SIEM JSON-логи.
            </p>
          </div>
          <div className="rounded-lg border border-[#2b2926] bg-[#1f1e1b] p-4">
            <div className="font-mono text-xs text-blue-400">ENTERPRISE GOV/FIN</div>
            <div className="text-xl font-bold mt-1">от 650 000 ₸ / мес</div>
            <p className="text-xs text-[#a09d96] mt-2">
              Air-gapped контур без выхода в интернет, кастомные правила комплаенса банков и госсектора, SLA и выделенный инстанс.
            </p>
          </div>
        </div>
      </dialog>
    </div>
  );
}

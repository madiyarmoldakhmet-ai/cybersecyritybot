'use client';

import { FormEvent, useCallback, useEffect, useId, useRef, useState } from 'react';
import { FileText, Play, ShieldCheck, Terminal, Upload, Wrench, X } from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import { SecurityScore } from '@/components/SecurityScore';
import { AiCopilotChat, ChatMessage } from '@/components/AiCopilotChat';
import { cn } from '@/lib/utils';

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

type WorkspaceView = 'studio' | 'chat' | 'audit';
type ConsoleTab = 'terminal' | 'findings';

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-[#e94a32]/20 text-[#ff8674] border border-[#e94a32]/50',
  HIGH: 'bg-orange-500/15 text-orange-300 border border-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border border-amber-500/40',
  LOW: 'bg-sky-500/15 text-sky-300 border border-sky-500/40',
  INFO: 'bg-neutral-500/20 text-neutral-300 border border-neutral-500/40',
};

const INITIAL_ASSISTANT_MESSAGE: ChatMessage = {
  id: 'welcome-1',
  role: 'assistant',
  content:
    'Commit Guardian AI на связи. Задай вопрос по безопасности кода, вставь ссылку **github.com/owner/repo**, прикрепи `.zip` скрепкой или нажми **«Демо-аудит»** — разберу каждую уязвимость и дам готовый патч.',
  timestamp: 'Сегодня',
};

function formatNowTime(): string {
  return new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

function formatCweShort(cwes?: string[]): string {
  if (!cwes || cwes.length === 0) return '—';
  const compact = cwes.map((c) => {
    const match = c.match(/CWE-\d+/i);
    return match ? match[0].toUpperCase() : c.split(':', 1)[0].trim();
  });
  const unique = Array.from(new Set(compact));
  return unique.slice(0, 2).join(', ');
}

export default function Home() {
  const [viewMode, setViewMode] = useState<WorkspaceView>('studio');
  const [consoleTab, setConsoleTab] = useState<ConsoleTab>('terminal');
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_ASSISTANT_MESSAGE]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  // Live backend & Ollama posture from /health
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null);
  const [ollamaModel, setOllamaModel] = useState<string>('qwen2.5-coder:14b');

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

  const heroZipInputId = useId();
  const chatWsRef = useRef<WebSocket | null>(null);
  const scanWsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startScanRef = useRef<(repoUrl: string) => void>(() => {});

  useEffect(() => {
    let active = true;
    const pollHealth = async () => {
      try {
        const res = await fetch('/health');
        if (!res.ok || !active) return;
        const data = await res.json();
        if (typeof data.ollama_online === 'boolean') setOllamaOnline(data.ollama_online);
        if (data.ollama_model) setOllamaModel(data.ollama_model);
      } catch {
        if (active) setOllamaOnline(false);
      }
    };
    pollHealth();
    const id = setInterval(pollHealth, 30000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

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
            return [
              ...prev,
              {
                id: 'streaming',
                role: 'assistant',
                content: data.content,
                timestamp: formatNowTime(),
              },
            ];
          });
        } else if (data.type === 'done') {
          setIsTyping(false);
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.id === 'streaming') {
              return [...prev.slice(0, -1), { ...last, id: `${Date.now()}` }];
            }
            return prev;
          });
        } else if (data.type === 'error') {
          setIsTyping(false);
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content: `Ошибка: ${data.message}`,
              timestamp: formatNowTime(),
            },
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
    setConsoleTab('terminal');
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
    if (list.length > 0) setConsoleTab('findings');

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

  const sendChatText = useCallback(
    (rawPrompt: string) => {
      const userMsg = rawPrompt.trim();
      if (!userMsg) return;

      const now = formatNowTime();
      setMessages((prev) => [...prev, { id: `${Date.now()}`, role: 'user', content: userMsg, timestamp: now }]);

      if (!chatWsRef.current || chatWsRef.current.readyState !== WebSocket.OPEN) {
        if (userMsg.includes('github.com/')) {
          const match = userMsg.split(/\s+/).find((w) => w.includes('github.com/'));
          if (match) startScanRef.current(match);
          return;
        }
        setMessages((prev) => [
          ...prev,
          {
            id: `${Date.now() + 1}`,
            role: 'assistant',
            content:
              'Соединение с `/ws/chat` временно закрыто. Отправьте ссылку `github.com/...`, прикрепите ZIP-архив или запустите «Демо-аудит».',
            timestamp: now,
          },
        ]);
        return;
      }

      setIsTyping(true);
      setMessages((prev) => [
        ...prev,
        { id: 'streaming', role: 'assistant', content: '', timestamp: now },
      ]);

      const payload = {
        message: userMsg,
        scan_context:
          findings.length > 0 || activeTarget
            ? {
                repo_name: activeTarget || 'workspace',
                security_score: securityScore,
                grade,
                total_findings: vulnerabilities,
                findings: findings.slice(0, 8),
              }
            : undefined,
      };
      chatWsRef.current.send(JSON.stringify(payload));
    },
    [activeTarget, findings, grade, securityScore, vulnerabilities]
  );

  const handleSendMessage = (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isTyping) return;
    const text = input;
    setInput('');
    sendChatText(text);
  };

  const handleResetChat = () => {
    setMessages([{ ...INITIAL_ASSISTANT_MESSAGE, id: `welcome-${Date.now()}` }]);
    setIsTyping(false);
    if (chatWsRef.current && chatWsRef.current.readyState === WebSocket.OPEN) {
      chatWsRef.current.send(JSON.stringify({ reset: true }));
    }
  };

  const handleDemoScan = async () => {
    if (viewMode === 'chat') setViewMode('studio');
    resetScanState('demo/kz-fintech-app');
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}`, role: 'user', content: 'Запусти демо-аудит KZ Fintech', timestamp: now },
      {
        id: 'streaming',
        role: 'assistant',
        content: 'Запускаю локальный аудит (SAST + Taint + Secrets + .aegis.yml)...',
        timestamp: now,
      },
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
              id: `${Date.now()}`,
              role: 'assistant',
              content: `Демо-аудит завершён: найдено **${data.total_findings}** уязвимостей, Score **${data.security_score}/100 (${data.grade})**. Спроси меня о любой находке или нажми «Патч» справа.`,
              timestamp: formatNowTime(),
            },
          ];
        }
        return [
          ...filtered,
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: `Ошибка демо-скана: ${data.error}`,
            timestamp: formatNowTime(),
          },
        ];
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
        {
          id: `${Date.now()}`,
          role: 'assistant',
          content: `Ошибка сети при демо-скане: ${err}`,
          timestamp: formatNowTime(),
        },
      ]);
    }
  };

  const handleZipUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setMessages((prev) => [
        ...prev,
        {
          id: `${Date.now()}`,
          role: 'assistant',
          content: 'Нужен архив формата `.zip`.',
          timestamp: formatNowTime(),
        },
      ]);
      return;
    }

    if (viewMode === 'chat') setViewMode('studio');
    resetScanState(`upload/${file.name}`);
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}`, role: 'user', content: `Проверь архив \`${file.name}\``, timestamp: now },
      {
        id: 'streaming',
        role: 'assistant',
        content: 'Распаковка в изолированную папку и локальный анализ...',
        timestamp: now,
      },
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
              id: `${Date.now()}`,
              role: 'assistant',
              content: `Аудит завершён: найдено **${data.total_findings ?? 0}** уязвимостей · Score **${data.security_score ?? '-'}/100 (${data.grade ?? '-'})**. Исходный код удалён с сервера.`,
              timestamp: formatNowTime(),
            },
          ];
        }
        return [
          ...filtered,
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: `Ошибка при сканировании: ${data.error || 'Неизвестная ошибка'}`,
            timestamp: formatNowTime(),
          },
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
        {
          id: `${Date.now()}`,
          role: 'assistant',
          content: `Ошибка сети при загрузке: ${err}`,
          timestamp: formatNowTime(),
        },
      ]);
    }
  };

  const startScan = (repoUrl: string) => {
    if (viewMode === 'chat') setViewMode('studio');
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
    <div className="min-h-screen bg-[var(--color-canvas)] text-[var(--color-ink)] font-sans flex flex-col swiss-grid-bg">
      <a href="#main-content" className="skip-link visually-hidden">
        Перейти к AI-чату и консоли
      </a>

      {/* Sticky 64px Top Navigation inspired by prtner.ai/font */}
      <header className="sticky top-0 z-30 min-h-16 border-b border-[var(--color-line)] bg-[var(--color-canvas)]/88 backdrop-blur-md">
        <div className="max-w-[1320px] mx-auto px-4 sm:px-6 lg:px-8 h-full py-2.5 flex flex-wrap md:flex-nowrap items-center justify-between gap-2 sm:gap-3">
          {/* Brand wordmark with vermilion dot (prtner.ai nod) */}
          <a
            href="#main-content"
            className="flex items-center gap-2 text-[var(--color-ink)] no-underline shrink-0"
          >
            <ShieldCheck className="w-5 h-5 text-[#e94a32]" aria-hidden="true" />
            <span className="font-sans text-lg font-medium tracking-tight">
              commit<span className="text-[#e94a32]">.</span>guardian
            </span>
          </a>

          {/* Segmented Architectural Mode Switcher (echoing Sans | Serif | Mono | Pixel) */}
          <nav aria-label="Основная навигация" className="flex flex-wrap items-center gap-1">
            {(
              [
                { id: 'studio', label: 'Студия' },
                { id: 'chat', label: 'AI-Чат' },
                { id: 'audit', label: 'Аудит' },
              ] as const
            ).map((tab) => {
              const active = viewMode === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setViewMode(tab.id)}
                  className={cn(
                    'min-h-9 px-3.5 text-sm transition-colors cursor-pointer border',
                    active
                      ? 'border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-ink)] font-medium'
                      : 'border-transparent text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                  )}
                >
                  {tab.label}
                </button>
              );
            })}
            <a
              href="/dashboard"
              className="min-h-9 px-3.5 text-sm border border-transparent text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] inline-flex items-center transition-colors"
            >
              Мониторинг
            </a>
          </nav>

          {/* Right controls & sharp high-contrast CTA */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => pricingDialogRef.current?.showModal()}
              className="hidden sm:inline-flex min-h-9 px-3 border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-paper)] text-xs font-mono uppercase tracking-wider items-center cursor-pointer transition-colors"
            >
              Тарифы ₸
            </button>
            <ThemeToggle />
            <button
              type="button"
              onClick={handleDemoScan}
              disabled={isScanning}
              className="min-h-9 px-4 bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-60 font-mono text-xs uppercase tracking-wider font-medium inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Демо-аудит</span>
            </button>
          </div>
        </div>
      </header>

      <main id="main-content" className="flex-1">
        {/* Compact Topographic Editorial Hero Band */}
        <section
          aria-label="Обзор платформы"
          className="border-b border-[var(--color-line)] bg-[var(--color-paper)]/60"
        >
          <div className="max-w-[1320px] mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            <div className="lg:col-span-8 space-y-3 min-w-0">
              <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                <span>01 · ON-PREM AI APPSEC</span>
                <span aria-hidden="true">·</span>
                <span className="inline-flex items-center gap-1.5 text-[var(--color-ink)]">
                  <span
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      ollamaOnline ? 'bg-emerald-500' : 'bg-[#e94a32]'
                    )}
                    aria-hidden="true"
                  />
                  {ollamaOnline ? `Ollama GPU · ${ollamaModel}` : `Air-Gapped · ${ollamaModel}`}
                </span>
              </div>

              <h1 className="font-sans font-light text-[clamp(2.1rem,3.8vw,3.35rem)] leading-[1.04] tracking-[-0.03em] text-[var(--color-ink)]">
                Commit Guardian — аудит кода и AI-чат без утечки в облако
              </h1>

              <p className="text-base text-[var(--color-body-text)] max-w-[68ch] leading-relaxed">
                Задавай вопросы локальной модели Qwen прямо в чате, проверяй GitHub-коммиты и ZIP-архивы на
                уязвимости, утечки ИИН/БИН и секреты по политике <code className="font-mono text-xs px-1.5 py-0.5 border border-[var(--color-line)]">.aegis.yml</code> с выгрузкой PDF-отчётов.
              </p>

              <div className="pt-1 flex flex-wrap items-center gap-2.5">
                <button
                  type="button"
                  onClick={handleDemoScan}
                  disabled={isScanning}
                  className="min-h-10 px-4 py-2 bg-[#e94a32] hover:bg-[#c83822] disabled:opacity-60 text-white font-mono text-xs uppercase tracking-wider inline-flex items-center gap-2 transition-colors cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Запустить демо-аудит (KZ Fintech)</span>
                </button>

                <input
                  id={heroZipInputId}
                  type="file"
                  accept=".zip"
                  className="visually-hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleZipUpload(file);
                    e.target.value = '';
                  }}
                />
                <button
                  type="button"
                  disabled={isScanning}
                  onClick={() => document.getElementById(heroZipInputId)?.click()}
                  className="min-h-10 px-4 py-2 border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] bg-[var(--color-canvas)] text-[var(--color-ink)] font-mono text-xs uppercase tracking-wider inline-flex items-center gap-2 transition-colors cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Проверить .ZIP</span>
                </button>

                <a
                  href="/dashboard"
                  className="min-h-10 px-4 py-2 border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] font-mono text-xs uppercase tracking-wider inline-flex items-center gap-2 transition-colors"
                >
                  <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Журнал аудитов</span>
                </a>
              </div>
            </div>

            {/* Minimal Swiss Topographic Mountain & Vermilion Sun Silhouette (subtle Medeo visual homage) */}
            <div className="hidden lg:flex lg:col-span-4 justify-end" aria-hidden="true">
              <div className="w-full max-w-[340px] border border-[var(--color-line)] bg-[#e9e9e6] text-[#141414] p-4 relative overflow-hidden">
                <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-[#6b6a65] mb-2">
                  <span>АЛАТАУ · КОНТУР ЗАЩИТЫ</span>
                  <span>0 BYTES OUT</span>
                </div>
                <svg viewBox="0 0 320 130" className="w-full h-auto block">
                  <circle cx="195" cy="48" r="32" fill="#e94a32" />
                  <path
                    d="M0 120 L48 76 L92 98 L148 48 L194 82 L242 36 L286 74 L320 56 L320 130 L0 130 Z"
                    fill="#141414"
                    fillOpacity="0.12"
                  />
                  <path
                    d="M0 120 L48 76 L92 98 L148 48 L194 82 L242 36 L286 74 L320 56"
                    fill="none"
                    stroke="#141414"
                    strokeWidth="1.5"
                  />
                  <circle cx="148" cy="48" r="3" fill="#ffffff" stroke="#141414" strokeWidth="1.5" />
                  <circle cx="242" cy="36" r="3" fill="#ffffff" stroke="#141414" strokeWidth="1.5" />
                </svg>
                <div className="mt-2 flex items-baseline justify-between font-mono text-[11px] text-[#141414] border-t border-black/10 pt-2">
                  <span className="font-serif text-base">On-Premise</span>
                  <span>SAST · TAINT · LLM</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Main 12-Column Architectural Workbench */}
        <section className="max-w-[1320px] mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
          <div className="flex flex-wrap items-baseline justify-between gap-2 pb-4 mb-5 border-b border-[var(--color-line)]">
            <div className="flex items-baseline gap-3">
              <span className="font-mono text-xs text-[#e94a32]">02</span>
              <h2 className="font-sans font-light text-2xl sm:text-3xl tracking-tight">
                {viewMode === 'chat'
                  ? 'Живой чат с локальным AI-ассистентом'
                  : viewMode === 'audit'
                  ? 'Результаты аудита и патчи безопасности'
                  : 'Четыре модуля, один контур'}
              </h2>
            </div>
            <span className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
              {activeTarget ? `Цель: ${activeTarget}` : 'Готов к проверке кода'}
            </span>
          </div>

          <div
            className={cn(
              'grid grid-cols-1 gap-4 items-stretch',
              viewMode === 'studio' ? 'lg:grid-cols-12' : 'lg:grid-cols-12'
            )}
          >
            {/* Primary Interactive AI Chat Card */}
            {viewMode !== 'audit' && (
              <div
                className={cn(
                  'min-w-0 flex flex-col',
                  viewMode === 'chat' ? 'lg:col-span-8 lg:col-start-3' : 'lg:col-span-5'
                )}
              >
                <AiCopilotChat
                  messages={messages}
                  input={input}
                  onInputChange={setInput}
                  onSubmit={handleSendMessage}
                  onQuickPrompt={(prompt) => sendChatText(prompt)}
                  onResetChat={handleResetChat}
                  onUploadZip={handleZipUpload}
                  isTyping={isTyping}
                  isScanning={isScanning}
                  ollamaOnline={ollamaOnline}
                  ollamaModel={ollamaModel}
                  activeTarget={activeTarget}
                  className="h-full"
                />
              </div>
            )}

            {/* Right Bento Console: Pixel Scoreboard, Paper Receipt, Telemetry Strip, Terminal/Findings */}
            {viewMode !== 'chat' && (
              <div
                className={cn(
                  'min-w-0 flex flex-col gap-4',
                  viewMode === 'audit' ? 'lg:col-span-12' : 'lg:col-span-7'
                )}
              >
                {/* Top Bento Row: Vermilion Pixel Scoreboard + Paper Compliance Receipt */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
                  <SecurityScore
                    score={securityScore}
                    grade={grade}
                    elapsedTime={elapsedTime}
                    vulnerabilities={vulnerabilities}
                    isScanning={isScanning}
                    reportPdfUrl={reportPdfUrl}
                    reportMdUrl={reportMdUrl}
                    className="md:col-span-5"
                  />

                  {/* Paper Specimen Audit Receipt Card modeled after Mono Receipt from prtner.ai */}
                  <div className="md:col-span-7 bg-[#f4f4f0] text-[#141414] border border-[var(--color-line)] p-5 flex flex-col justify-between gap-4">
                    <div className="flex items-baseline justify-between gap-2 pb-3 border-b border-[#d8d7d0]">
                      <span className="font-mono text-2xl tracking-tight leading-none text-[#141414]">
                        Чек
                      </span>
                      <span className="font-mono text-xs uppercase tracking-wider text-[#6b6a65]">
                        Политика .aegis.yml
                      </span>
                    </div>

                    <div className="bg-white border border-[#d8d7d0] p-4 font-mono text-xs space-y-2 tabular-nums">
                      <div className="text-center font-medium uppercase tracking-wider text-[#141414] pb-1">
                        COMMIT GUARDIAN AUDIT
                      </div>
                      <div className="border-t border-dashed border-[#c8c7bf] pt-2 space-y-1.5">
                        <div className="flex items-baseline gap-2">
                          <span className="text-[#6b6a65]">SAST + Taint</span>
                          <span className="spec-leader" aria-hidden="true" />
                          <span>Активен</span>
                        </div>
                        <div className="flex items-baseline gap-2">
                          <span className="text-[#6b6a65]">Секреты / ИИН РК</span>
                          <span className="spec-leader" aria-hidden="true" />
                          <span>Фильтр включён</span>
                        </div>
                        <div className="flex items-baseline gap-2">
                          <span className="text-[#6b6a65]">Локальный ИИ</span>
                          <span className="spec-leader" aria-hidden="true" />
                          <span className="truncate max-w-[160px]">{ollamaModel}</span>
                        </div>
                        <div className="flex items-baseline gap-2">
                          <span className="text-[#6b6a65]">Передача в облако</span>
                          <span className="spec-leader" aria-hidden="true" />
                          <span>0 ₸ / 0 байт</span>
                        </div>
                      </div>
                      <div className="border-t border-dashed border-[#c8c7bf] pt-2 flex items-baseline justify-between font-medium text-[#141414]">
                        <span>Вердикт</span>
                        <span>
                          {securityScore === null
                            ? 'Ожидает проверки'
                            : `${securityScore}/100 · Grade ${grade || '-'}`}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-[#3e3e3a] leading-relaxed">
                      {auditSummary
                        ? auditSummary
                        : 'После запуска аудита здесь появится сводное заключение аудитора и ссылки на официальный PDF/Markdown-отчёт.'}
                    </p>
                  </div>
                </div>

                {/* Sharp 4-Cell Telemetry Strip */}
                <MetricsDashboard
                  scannedFiles={scannedFiles}
                  totalFiles={totalFiles}
                  vulnerabilities={vulnerabilities}
                  elapsedTime={elapsedTime}
                  ollamaOnline={ollamaOnline}
                  ollamaModel={ollamaModel}
                  isScanning={isScanning}
                />

                {/* Terminal / Findings Panel */}
                <div className="flex flex-col flex-1 min-h-0">
                  <div className="flex items-center justify-between border border-b-0 border-[var(--color-line)] bg-[var(--color-paper)] px-4 py-2">
                    <div className="flex items-center gap-1" role="tablist" aria-label="Режим консоли">
                      <button
                        type="button"
                        role="tab"
                        aria-selected={consoleTab === 'terminal'}
                        onClick={() => setConsoleTab('terminal')}
                        className={cn(
                          'min-h-8 px-3 font-mono text-xs uppercase tracking-wider inline-flex items-center gap-1.5 cursor-pointer border',
                          consoleTab === 'terminal'
                            ? 'border-[var(--color-line-strong)] bg-[var(--color-canvas)] text-[var(--color-ink)]'
                            : 'border-transparent text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                        )}
                      >
                        <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Логи</span>
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={consoleTab === 'findings'}
                        onClick={() => setConsoleTab('findings')}
                        className={cn(
                          'min-h-8 px-3 font-mono text-xs uppercase tracking-wider inline-flex items-center gap-1.5 cursor-pointer border',
                          consoleTab === 'findings'
                            ? 'border-[var(--color-line-strong)] bg-[var(--color-canvas)] text-[var(--color-ink)]'
                            : 'border-transparent text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                        )}
                      >
                        <Wrench className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Уязвимости ({findings.length})</span>
                      </button>
                    </div>
                    <span className="font-mono text-[11px] text-[var(--color-muted-soft)] hidden sm:inline">
                      {activeTarget || 'demo/kz-fintech-app ready'}
                    </span>
                  </div>

                  {consoleTab === 'findings' && findings.length > 0 ? (
                    <div
                      tabIndex={0}
                      role="region"
                      aria-labelledby="findings-caption"
                      className="table-wrapper cg-scroll bg-[#111111] text-[#ededed] border border-[var(--color-line)] flex-1"
                    >
                      <table className="findings-table w-full table-fixed text-left text-xs">
                        <caption id="findings-caption" className="visually-hidden">
                          Обнаруженные уязвимости исходного кода
                        </caption>
                        <thead>
                          <tr className="text-[#8f8f8f] border-b border-[#242424] font-mono uppercase text-[11px]">
                            <th scope="col" className="p-3 font-medium w-[92px]">Уровень</th>
                            <th scope="col" className="p-3 font-medium">Уязвимость и файл</th>
                            <th scope="col" className="p-3 font-medium w-[90px]">CWE</th>
                            <th scope="col" className="p-3 font-medium w-[112px] text-right">Патч</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#242424]">
                          {findings.map((f, idx) => (
                            <tr key={`${f.id}-${idx}`} className="hover:bg-[#181818] transition-colors">
                              <td data-label="Уровень" className="p-3 whitespace-nowrap align-top">
                                <span
                                  className={cn(
                                    'px-2 py-0.5 font-mono text-[11px] uppercase',
                                    SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO
                                  )}
                                >
                                  {f.severity}
                                </span>
                              </td>
                              <th scope="row" className="p-3 font-normal align-top min-w-0">
                                <div className="font-medium text-[#ededed] break-words">{f.title}</div>
                                <div className="font-mono text-[11px] text-[#8f8f8f] mt-0.5 break-all">
                                  {f.file_path}:{f.line_start || 1} · {f.scanner}
                                </div>
                              </th>
                              <td
                                data-label="CWE"
                                title={f.cwe?.join(', ') || ''}
                                className="p-3 font-mono text-[#8f8f8f] whitespace-nowrap align-top truncate"
                              >
                                {formatCweShort(f.cwe)}
                              </td>
                              <td data-label="Патч" className="p-3 text-right whitespace-nowrap align-top">
                                <button
                                  type="button"
                                  onClick={() => handleOpenRemediation(f)}
                                  className="min-h-8 px-2.5 py-1 bg-[#242424] hover:bg-[#e94a32] text-[#ededed] hover:text-white font-mono text-[11px] uppercase tracking-wider inline-flex items-center gap-1 transition-colors cursor-pointer"
                                >
                                  <Wrench className="w-3 h-3" aria-hidden="true" />
                                  <span>Патч</span>
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <TerminalWindow
                      events={events}
                      targetLabel={activeTarget}
                      className="flex-1"
                    />
                  )}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Bottom Architectural Architecture Band (prtner.ai «Почему Medeo» rhythm) */}
        <section
          aria-label="Приватность и архитектура"
          className="border-t border-[var(--color-line)] bg-[var(--color-paper)]/50"
        >
          <div className="max-w-[1320px] mx-auto px-4 sm:px-6 lg:px-8 py-10 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <div className="lg:col-span-6 space-y-3">
              <span className="font-mono text-xs uppercase tracking-wider text-[#e94a32]">
                03 · ПОЧЕМУ ON-PREMISE
              </span>
              <h2 className="font-serif text-3xl sm:text-4xl tracking-tight leading-tight">
                Банкам и госсектору нельзя отправлять код в публичные облака
              </h2>
              <p className="text-sm sm:text-base text-[var(--color-body-text)] leading-relaxed max-w-[60ch]">
                Любой публичный ИИ-помощник нарушает внутренние политики безопасности. Commit Guardian разворачивается
                в закрытом контуре Docker или на выделенном GPU-сервере: код, ИИН/БИН клиентов и отчёты остаются
                строго внутри периметра компании.
              </p>
            </div>

            <div className="lg:col-span-6 bg-[#f4f4f0] text-[#141414] border border-[var(--color-line)] p-6 space-y-3">
              <div className="font-mono text-xs uppercase tracking-wider text-[#6b6a65]">
                АРХИТЕКТУРА B2B ВНЕДРЕНИЯ
              </div>
              <div className="space-y-2 font-mono text-xs sm:text-sm">
                <div className="flex items-baseline gap-2">
                  <span>Статический движок</span>
                  <span className="spec-leader" aria-hidden="true" />
                  <span>Semgrep · Bandit · Custom AST</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span>ИИ-копилот и фиксы</span>
                  <span className="spec-leader" aria-hidden="true" />
                  <span>Ollama Qwen2.5-Coder 14B/32B</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span>Алерты команде</span>
                  <span className="spec-leader" aria-hidden="true" />
                  <span>GitHub PR · Telegram PDF</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span>Тарифы для РК</span>
                  <span className="spec-leader" aria-hidden="true" />
                  <span>от 0 ₸ (Pilot) до Enterprise</span>
                </div>
              </div>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => pricingDialogRef.current?.showModal()}
                  className="min-h-10 px-4 py-2 bg-[#141414] hover:bg-[#e94a32] text-[#faf9f5] font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
                >
                  Смотреть тарифы и SLA
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-[var(--color-line)] bg-[var(--color-canvas)] py-5">
        <div className="max-w-[1320px] mx-auto px-4 sm:px-6 lg:px-8 flex flex-wrap items-center justify-between gap-3 font-mono text-xs text-[var(--color-muted-soft)]">
          <div>
            commit<span className="text-[#e94a32]">.</span>guardian · On-Premise DevSecOps Security
          </div>
          <div className="flex items-center gap-4">
            <a href="/dashboard" className="hover:text-[var(--color-ink)] transition-colors">
              /dashboard
            </a>
            <a href="/docs" className="hover:text-[var(--color-ink)] transition-colors">
              /docs API
            </a>
            <span>Типографика: Medeo OFL 1.1</span>
          </div>
        </div>
      </footer>

      {/* Native <dialog>: AI Remediation & Diff Modal */}
      <dialog
        ref={fixDialogRef}
        aria-labelledby="remediation-dialog-title"
        className="m-auto w-[min(92vw,740px)] border border-[#242424] bg-[#111111] text-[#ededed] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-4 pb-3 border-b border-[#242424]">
          <div>
            <h2 id="remediation-dialog-title" className="font-serif text-2xl">
              {selectedFinding?.title || 'Патч безопасности'}
            </h2>
            {selectedFinding && (
              <p className="text-xs font-mono text-[#8f8f8f] mt-1">
                {selectedFinding.file_path}:{selectedFinding.line_start || 1} ·{' '}
                {selectedFinding.cwe?.join(', ') || 'SAST'}
              </p>
            )}
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть окно патча"
              className="min-h-9 min-w-9 p-1.5 border border-[#242424] hover:border-[#e94a32] text-[#8f8f8f] hover:text-white cursor-pointer inline-flex items-center justify-center"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>

        {isFixing ? (
          <div className="py-8 text-sm font-mono text-[#8f8f8f]">
            Генерирую безопасный патч локальным движком...
          </div>
        ) : remediation ? (
          <div className="space-y-4 text-sm">
            <div>
              <div className="text-xs font-mono uppercase text-[#8f8f8f] mb-1">Причина и риск</div>
              <p className="text-[#ededed] leading-relaxed">{remediation.explanation_ru}</p>
              <p className="text-[#e94a32] text-xs mt-1">{remediation.impact_analysis}</p>
            </div>
            {remediation.remediation_steps.length > 0 && (
              <div>
                <div className="text-xs font-mono uppercase text-[#8f8f8f] mb-1">Как устранить</div>
                <ul className="list-disc pl-5 space-y-1 text-xs text-[#d6d3cd]">
                  {remediation.remediation_steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
            <div>
              <div className="text-xs font-mono uppercase text-[#8f8f8f] mb-1">Безопасный код</div>
              <pre className="p-3 bg-[#0a0a0a] border border-[#242424] font-mono text-xs overflow-x-auto text-emerald-400">
                {remediation.fixed_code}
              </pre>
            </div>
          </div>
        ) : (
          <p className="text-sm text-[#8f8f8f]">
            {selectedFinding?.recommendation || selectedFinding?.description || 'Не удалось получить патч.'}
          </p>
        )}
      </dialog>

      {/* Native <dialog>: On-Premise Architecture & KZ B2B Pricing */}
      <dialog
        ref={pricingDialogRef}
        aria-labelledby="pricing-dialog-title"
        className="m-auto w-[min(92vw,780px)] border border-[#242424] bg-[#111111] text-[#ededed] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-5 pb-3 border-b border-[#242424]">
          <div>
            <h2 id="pricing-dialog-title" className="font-serif text-2xl">
              On-Premise архитектура и тарифы B2B
            </h2>
            <p className="text-xs text-[#8f8f8f] mt-1">
              Модель B2B-подписки внутри закрытого контура компании: исходный код и ПДн не покидают серверы заказчика.
            </p>
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть тарифы"
              className="min-h-9 min-w-9 p-1.5 border border-[#242424] hover:border-[#e94a32] text-[#8f8f8f] hover:text-white cursor-pointer inline-flex items-center justify-center"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="border border-[#242424] bg-[#161616] p-4">
            <div className="font-mono text-xs text-emerald-400">PILOT</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">0 ₸ / 14 дней</div>
            <p className="text-xs text-[#8f8f8f] mt-2 leading-relaxed">
              1–2 репозитория, Docker-развёртывание, алерты в Telegram и Compliance PDF для команды до 5 разработчиков.
            </p>
          </div>
          <div className="border border-[#e94a32] bg-[#161616] p-4">
            <div className="font-mono text-xs text-[#e94a32]">TEAM ON-PREM</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">190 000 ₸ / мес</div>
            <p className="text-xs text-[#8f8f8f] mt-2 leading-relaxed">
              До 25 разработчиков, локальная Ollama, политики .aegis.yml (ИИН/ПДн), авто-комментарии в PR и SIEM JSON-логи.
            </p>
          </div>
          <div className="border border-[#242424] bg-[#161616] p-4">
            <div className="font-mono text-xs text-sky-400">ENTERPRISE GOV/FIN</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">от 650 000 ₸ / мес</div>
            <p className="text-xs text-[#8f8f8f] mt-2 leading-relaxed">
              Air-gapped контур без выхода в интернет, кастомные правила комплаенса банков и госсектора, SLA и выделенный инстанс.
            </p>
          </div>
        </div>
      </dialog>
    </div>
  );
}

'use client';

import { FormEvent, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  Flag,
  GitPullRequest,
  HeartPulse,
  Lock,
  Play,
  ShieldCheck,
  Terminal,
  Undo2,
  Upload,
  Wrench,
  X,
} from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import { SecurityScore } from '@/components/SecurityScore';
import { AiCopilotChat, ChatMessage } from '@/components/AiCopilotChat';
import { AuthorshipPanel, AuthorshipState } from '@/components/AuthorshipPanel';
import {
  FinancialRisk,
  GhostSecret,
  GhostSecretsCard,
  HealPanel,
  HealingReport,
  RiskCard,
  formatKzt,
} from '@/components/GuardianInsights';
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
  raw_metadata?: Record<string, unknown>;
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
  syntax_validated?: boolean;
  validation_note?: string | null;
};

type AppealRecord = {
  appealId?: number;
  reason: string;
};

const WORKSPACE_STORAGE_KEY = 'commit_guardian_workspace_v1';

const SEVERITY_PENALTY: Record<string, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0,
};

function makeFindingKey(f: Finding): string {
  return `${f.id}::${f.file_path}::${f.line_start || 1}`;
}

function computeLocalScore(activeFindings: Finding[]): { score: number; grade: string } {
  let score = 100;
  for (const f of activeFindings) {
    score -= SEVERITY_PENALTY[f.severity?.toUpperCase()] ?? 0;
  }
  const clamped = Math.max(0, Math.min(100, score));
  const grade =
    clamped >= 90 ? 'A+' : clamped >= 80 ? 'A' : clamped >= 70 ? 'B' : clamped >= 60 ? 'C' : clamped >= 40 ? 'D' : 'F';
  return { score: clamped, grade };
}

type InspectorTab = 'overview' | 'authorship' | 'scanner' | 'findings';

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-[#e94a32]/15 text-[#ff735d] border border-[#e94a32]/40',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/35',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border border-amber-500/35',
  LOW: 'bg-sky-500/15 text-sky-400 border border-sky-500/35',
  INFO: 'bg-neutral-500/15 text-[var(--color-muted-soft)] border border-[var(--color-line)]',
};

const INITIAL_ASSISTANT_MESSAGE: ChatMessage = {
  id: 'welcome-1',
  role: 'assistant',
  content:
    'На связи **Commit Guardian AI**. Спрашивай о безопасности кода, прикрепи `.zip` скрепкой, вставь ссылку `github.com/owner/repo` или запусти **«Демо-аудит»** — проверю уязвимости, утечки ИИН и помогу подтвердить авторство.',
  timestamp: 'Сегодня',
};

const EMPTY_AUTHORSHIP: AuthorshipState = {
  verified: false,
  target: '',
  targetType: 'github',
  method: 'challenge',
  actor: '',
  role: 'None',
  canCreatePr: false,
  message: '',
  proofToken: '',
  githubToken: '',
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
  return Array.from(new Set(compact)).slice(0, 2).join(', ');
}

export default function Home() {
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('overview');
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_ASSISTANT_MESSAGE]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  // Live backend & Ollama posture
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null);
  const [ollamaModel, setOllamaModel] = useState<string>('qwen2.5-coder:14b');

  // Authorship verification state
  const [verifyTarget, setVerifyTarget] = useState('https://github.com/madiyarmoldakhmet-ai/cybersecyritybot');
  const [authorship, setAuthorship] = useState<AuthorshipState>(EMPTY_AUTHORSHIP);
  const [requireOwnership, setRequireOwnership] = useState(false);
  const [repoScanUrl, setRepoScanUrl] = useState('');

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
  const [auditAuthorshipLabel, setAuditAuthorshipLabel] = useState<string>('—');
  const [reportPdfUrl, setReportPdfUrl] = useState<string | null>(null);
  const [reportMdUrl, setReportMdUrl] = useState<string | null>(null);
  const [activeTarget, setActiveTarget] = useState<string>('');
  const [financialRisk, setFinancialRisk] = useState<FinancialRisk | null>(null);
  const [healReport, setHealReport] = useState<HealingReport | null>(null);
  const [isHealing, setIsHealing] = useState(false);
  const [appealedMap, setAppealedMap] = useState<Record<string, AppealRecord>>({});
  const [hydrated, setHydrated] = useState(false);

  const ghostSecrets = useMemo<GhostSecret[]>(() => {
    const out: GhostSecret[] = [];
    for (const f of findings) {
      const gh = f.raw_metadata?.git_history as GhostSecret | undefined;
      if (gh && gh.introduced && gh.masked_value) {
        out.push(gh);
      }
    }
    return out;
  }, [findings]);

  const activeFindingsCount = useMemo(
    () => findings.filter((f) => !appealedMap[makeFindingKey(f)]).length,
    [findings, appealedMap]
  );
  const appealedCount = Object.keys(appealedMap).length;

  // Dialogs
  const pricingDialogRef = useRef<HTMLDialogElement>(null);
  const fixDialogRef = useRef<HTMLDialogElement>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [remediation, setRemediation] = useState<RemediationResult | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const [prStatus, setPrStatus] = useState<string>('');
  const [creatingPr, setCreatingPr] = useState(false);

  const zipInputId = useId();
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
              { id: 'streaming', role: 'assistant', content: data.content, timestamp: formatNowTime() },
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
            { id: `${Date.now()}`, role: 'assistant', content: `Ошибка: ${data.message}`, timestamp: formatNowTime() },
          ]);
        }
      };

      ws.onclose = () => {
        if (!unmounted) reconnectTimer = setTimeout(connectChatWs, 3000);
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

  // Persist & restore audit session across F5 browser refreshes
  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      const raw = window.localStorage.getItem(WORKSPACE_STORAGE_KEY);
      if (raw) {
        const saved = JSON.parse(raw);
        if (saved && typeof saved === 'object') {
          if (typeof saved.activeTarget === 'string') setActiveTarget(saved.activeTarget);
          if (Array.isArray(saved.findings)) setFindings(saved.findings);
          if (typeof saved.securityScore === 'number') setSecurityScore(saved.securityScore);
          if (typeof saved.grade === 'string') setGrade(saved.grade);
          if (typeof saved.auditSummary === 'string') setAuditSummary(saved.auditSummary);
          if (typeof saved.elapsedTime === 'number') setElapsedTime(saved.elapsedTime);
          if (typeof saved.vulnerabilities === 'number') setVulnerabilities(saved.vulnerabilities);
          if (typeof saved.scannedFiles === 'number') setScannedFiles(saved.scannedFiles);
          if (typeof saved.totalFiles === 'number') setTotalFiles(saved.totalFiles);
          if (saved.reportPdfUrl) setReportPdfUrl(saved.reportPdfUrl);
          if (saved.reportMdUrl) setReportMdUrl(saved.reportMdUrl);
          if (saved.financialRisk) setFinancialRisk(saved.financialRisk);
          if (saved.healReport) setHealReport(saved.healReport);
          if (saved.appealedMap && typeof saved.appealedMap === 'object') setAppealedMap(saved.appealedMap);
          if (Array.isArray(saved.findings) && saved.findings.length > 0) setInspectorTab('findings');
        }
      }
    } catch {
      // Ignore malformed localStorage payload
    } finally {
      setHydrated(true);
    }
  }, []);

  useEffect(() => {
    if (!hydrated || typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(
        WORKSPACE_STORAGE_KEY,
        JSON.stringify({
          activeTarget,
          findings,
          securityScore,
          grade,
          auditSummary,
          elapsedTime,
          vulnerabilities,
          scannedFiles,
          totalFiles,
          reportPdfUrl,
          reportMdUrl,
          financialRisk,
          healReport,
          appealedMap,
        })
      );
    } catch {
      // Ignore storage quota errors
    }
  }, [
    hydrated,
    activeTarget,
    findings,
    securityScore,
    grade,
    auditSummary,
    elapsedTime,
    vulnerabilities,
    scannedFiles,
    totalFiles,
    reportPdfUrl,
    reportMdUrl,
    financialRisk,
    healReport,
    appealedMap,
  ]);

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
    setFinancialRisk(null);
    setHealReport(null);
    setAppealedMap({});
    setActiveTarget(targetLabel);
    setAuditAuthorshipLabel(authorship.verified ? `Подтверждён (${authorship.role})` : 'Локально / Read-Only');
    setInspectorTab('scanner');
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
    authorship_status?: string;
    report_pdf_url?: string | null;
    report_md_url?: string | null;
    financial_risk?: FinancialRisk | null;
    scan_result?: { duration_seconds?: number };
    duration_seconds?: number;
  }) => {
    const list = data.vulnerabilities || data.findings || [];
    setFindings(list);
    setVulnerabilities(data.total_findings ?? list.length);
    if (typeof data.security_score === 'number') setSecurityScore(data.security_score);
    if (data.grade) setGrade(data.grade);
    if (data.summary) setAuditSummary(data.summary);
    if (data.authorship_status) setAuditAuthorshipLabel(data.authorship_status);
    setReportPdfUrl(data.report_pdf_url ?? null);
    setReportMdUrl(data.report_md_url ?? null);
    setFinancialRisk(data.financial_risk ?? null);
    setHealReport(null);
    setAppealedMap({});
    if (typeof data.scan_result?.duration_seconds === 'number') {
      setElapsedTime(data.scan_result.duration_seconds);
    } else if (typeof data.duration_seconds === 'number') {
      setElapsedTime(data.duration_seconds);
    }
    setIsScanning(false);
    if (timerRef.current) clearInterval(timerRef.current);
    if (list.length > 0) setInspectorTab('findings');

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
    async (rawPrompt: string) => {
      const userMsg = rawPrompt.trim();
      if (!userMsg) return;

      const now = formatNowTime();
      setMessages((prev) => [...prev, { id: `${Date.now()}`, role: 'user', content: userMsg, timestamp: now }]);

      const scanContext =
        findings.length > 0 || activeTarget
          ? {
              repo_name: activeTarget || 'workspace',
              security_score: securityScore,
              grade,
              total_findings: activeFindingsCount,
              financial_risk: financialRisk,
              findings: findings.filter((f) => !appealedMap[makeFindingKey(f)]).slice(0, 8),
            }
          : undefined;

      if (!chatWsRef.current || chatWsRef.current.readyState !== WebSocket.OPEN) {
        if (userMsg.includes('github.com/')) {
          const match = userMsg.split(/\s+/).find((w) => w.includes('github.com/'));
          if (match) {
            startScanRef.current(match);
            return;
          }
        }
        setIsTyping(true);
        setMessages((prev) => [...prev, { id: 'streaming', role: 'assistant', content: '', timestamp: now }]);
        try {
          const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: userMsg, scan_context: scanContext }),
          });
          const data = await res.json();
          setIsTyping(false);
          if (data.action === 'SCAN' && data.github_url) {
            startScanRef.current(data.github_url);
          }
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            {
              id: `${Date.now() + 1}`,
              role: 'assistant',
              content: data.reply || 'Запрос обработан.',
              timestamp: formatNowTime(),
            },
          ]);
        } catch {
          setIsTyping(false);
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            {
              id: `${Date.now() + 1}`,
              role: 'assistant',
              content: 'Не удалось доставить сообщение. Повторите запрос или запустите «Демо-аудит».',
              timestamp: formatNowTime(),
            },
          ]);
        }
        return;
      }

      setIsTyping(true);
      setMessages((prev) => [...prev, { id: 'streaming', role: 'assistant', content: '', timestamp: now }]);

      chatWsRef.current.send(
        JSON.stringify({
          message: userMsg,
          scan_context: scanContext,
        })
      );
    },
    [activeTarget, findings, grade, securityScore, activeFindingsCount, financialRisk, appealedMap]
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
    resetScanState('demo/kz-fintech-app');
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}`, role: 'user', content: 'Запусти демо-аудит KZ Fintech', timestamp: now },
      { id: 'streaming', role: 'assistant', content: 'Запускаю локальный аудит (SAST + Taint + Secrets)...', timestamp: now },
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
              content: `Демо-аудит завершён: **${data.total_findings}** находок, Score **${data.security_score}/100 (${data.grade})**. Спроси о любой уязвимости или жми «Патч» справа.`,
              timestamp: formatNowTime(),
            },
          ];
        }
        return [...filtered, { id: `${Date.now()}`, role: 'assistant', content: `Ошибка демо-скана: ${data.error}`, timestamp: formatNowTime() }];
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
        { id: `${Date.now()}`, role: 'assistant', content: `Ошибка сети при демо-скане: ${err}`, timestamp: formatNowTime() },
      ]);
    }
  };

  const handleZipUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setMessages((prev) => [...prev, { id: `${Date.now()}`, role: 'assistant', content: 'Нужен архив формата `.zip`.', timestamp: formatNowTime() }]);
      return;
    }

    resetScanState(`upload/${file.name}`);
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}`, role: 'user', content: `Проверь архив \`${file.name}\``, timestamp: now },
      { id: 'streaming', role: 'assistant', content: 'Распаковка и локальный анализ...', timestamp: now },
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
              content: `Аудит завершён: **${data.total_findings ?? 0}** находок · Score **${data.security_score ?? '-'}/100 (${data.grade ?? '-'})**. Исходный код удалён.`,
              timestamp: formatNowTime(),
            },
          ];
        }
        return [...filtered, { id: `${Date.now()}`, role: 'assistant', content: `Ошибка при сканировании: ${data.error || 'Неизвестная ошибка'}`, timestamp: formatNowTime() }];
      });
      if (res.ok) applyCompletedPayload(data);
      else {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    } catch (err) {
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'streaming'),
        { id: `${Date.now()}`, role: 'assistant', content: `Ошибка сети при загрузке: ${err}`, timestamp: formatNowTime() },
      ]);
    }
  };

  const startScan = (repoUrl: string) => {
    const clean = repoUrl.trim();
    if (!clean) return;
    setRepoScanUrl(clean);
    setVerifyTarget(clean);
    resetScanState(clean);
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/scan`;
    const ws = new WebSocket(wsUrl);
    scanWsRef.current = ws;

    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          github_url: clean,
          github_token: authorship.githubToken || undefined,
          proof_token: authorship.proofToken || undefined,
          require_ownership: requireOwnership,
        })
      );
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
      } else if (data.event_type === 'SystemError') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        setMessages((prev) => [
          ...prev,
          { id: `${Date.now()}`, role: 'assistant', content: `⛔ ${data.message}`, timestamp: formatNowTime() },
        ]);
      } else if (data.event_type === 'ScanCompleted') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };
  };

  useEffect(() => {
    startScanRef.current = startScan;
  });

  const handleDemoHeal = async () => {
    if (isHealing) return;
    setIsHealing(true);
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev,
      { id: `${Date.now()}`, role: 'user', content: 'Запусти самоисцеление с доказательством (Self-Heal)', timestamp: now },
      { id: 'streaming', role: 'assistant', content: 'Патчу копию кода через AST → ast.parse() → пересканирую песочницу...', timestamp: now },
    ]);
    try {
      const res = await fetch('/api/scan/demo/heal', { method: 'POST' });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'streaming');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content:
                `Самоисцеление подтверждено пересканированием: Score **${data.before_score} (${data.before_grade}) → ${data.after_score} (${data.after_grade})**, ` +
                `находки **${data.before_findings} → ${data.after_findings}**, риск **${formatKzt(data.before_risk_kzt)} → ${formatKzt(data.after_risk_kzt)}**. ` +
                `Проверенные unified diffs — в карточке ниже.`,
              timestamp: formatNowTime(),
            },
          ];
        }
        return [
          ...filtered,
          { id: `${Date.now()}`, role: 'assistant', content: `Ошибка самоисцеления: ${data.error || 'unknown'}`, timestamp: formatNowTime() },
        ];
      });
      if (res.ok) {
        setHealReport(data);
        setTimeout(() => document.getElementById('guardian-insights')?.scrollIntoView({ behavior: 'smooth' }), 120);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'streaming'),
        { id: `${Date.now()}`, role: 'assistant', content: `Ошибка сети при самоисцелении: ${err}`, timestamp: formatNowTime() },
      ]);
    } finally {
      setIsHealing(false);
    }
  };

  const handleToggleAppeal = async (finding: Finding) => {
    const key = makeFindingKey(finding);
    const existing = appealedMap[key];

    if (existing) {
      const nextMap = { ...appealedMap };
      delete nextMap[key];
      setAppealedMap(nextMap);
      const active = findings.filter((f) => !nextMap[makeFindingKey(f)]);
      const next = computeLocalScore(active);
      setSecurityScore(next.score);
      setGrade(next.grade);
      setVulnerabilities(active.length);
      if (existing.appealId) {
        try {
          await fetch(`/api/v1/findings/appeal/${existing.appealId}`, { method: 'DELETE' });
        } catch {
          // Local state already reverted cleanly
        }
      }
      return;
    }

    const nextMap: Record<string, AppealRecord> = {
      ...appealedMap,
      [key]: { reason: 'Оспорено разработчиком как False Positive' },
    };
    const active = findings.filter((f) => !nextMap[makeFindingKey(f)]);
    const localNext = computeLocalScore(active);
    setAppealedMap(nextMap);
    setSecurityScore(localNext.score);
    setGrade(localNext.grade);
    setVulnerabilities(active.length);

    try {
      const res = await fetch('/api/v1/findings/appeal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_name: activeTarget || 'workspace',
          finding_key: key,
          finding_title: finding.title,
          severity: finding.severity,
          status: 'false_positive',
          reason: 'Оспорено разработчиком в веб-консоли (Human-in-the-Loop)',
          reviewer: authorship.actor || 'developer',
          remaining_severities: active.map((f) => f.severity),
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (typeof data.adjusted_score === 'number') setSecurityScore(data.adjusted_score);
        if (data.adjusted_grade) setGrade(data.adjusted_grade);
        if (data.appeal?.id) {
          setAppealedMap((prev) => ({
            ...prev,
            [key]: { appealId: data.appeal.id, reason: data.appeal.reason || 'False Positive' },
          }));
        }
      }
    } catch {
      // Optimistic local calculation remains active
    }
  };

  const handleOpenRemediation = async (finding: Finding) => {
    setSelectedFinding(finding);
    setRemediation(null);
    setPrStatus('');
    setIsFixing(true);
    fixDialogRef.current?.showModal();

    try {
      const res = await fetch('/api/v1/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, code_context: finding.code_snippet || '' }),
      });
      if (res.ok) setRemediation(await res.json());
    } catch {
      // Handled smoothly in modal UI
    } finally {
      setIsFixing(false);
    }
  };

  const handleCreatePR = async () => {
    if (!selectedFinding || !remediation || !authorship.githubToken || !activeTarget) return;
    setCreatingPr(true);
    setPrStatus('');
    try {
      const res = await fetch('/api/v1/pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: activeTarget,
          github_token: authorship.githubToken,
          file_path: selectedFinding.file_path,
          finding: selectedFinding,
          remediation,
        }),
      });
      const data = await res.json();
      if (res.ok && data.pull_request_url) {
        setPrStatus(`PR создан: ${data.pull_request_url}`);
      } else {
        setPrStatus(data.detail || data.message || 'Не удалось создать PR.');
      }
    } catch (err) {
      setPrStatus(`Ошибка: ${err}`);
    } finally {
      setCreatingPr(false);
    }
  };

  const pipelineStage =
    securityScore !== null
      ? 4
      : isScanning
      ? 3
      : activeTarget
      ? 2
      : authorship.verified
      ? 1
      : 1;

  return (
    <div className="min-h-screen bg-[var(--color-canvas)] text-[var(--color-ink)] font-sans flex flex-col">
      <a href="#workspace" className="skip-link visually-hidden">
        Перейти к рабочей области и AI-чату
      </a>

      {/* Sticky 64px Obsidian Header modeled on prtner.ai */}
      <header className="sticky top-0 z-30 h-16 border-b border-[var(--color-line)] bg-[var(--color-canvas)]/82 backdrop-blur-md">
        <div className="max-w-[1160px] mx-auto px-5 h-full flex items-center justify-between gap-4">
          <a href="#workspace" className="flex items-center gap-2.5 text-[var(--color-ink)] no-underline shrink-0">
            <span className="grid grid-cols-2 gap-0.5 w-4 h-4 shrink-0" aria-hidden="true">
              <span className="bg-[#e94a32]" />
              <span className="bg-[var(--color-ink)]" />
              <span className="bg-[var(--color-ink)]" />
              <span className="bg-[var(--color-ink)] opacity-45" />
            </span>
            <span className="font-sans text-[17px] font-medium tracking-tight">
              commit<span className="text-[#e94a32]">.</span>guardian
            </span>
          </a>

          <nav aria-label="Основная навигация" className="hidden md:flex items-center gap-6 text-sm text-[var(--color-muted-soft)]">
            <a href="#workspace" className="hover:text-[var(--color-ink)] transition-colors">
              AI-чат
            </a>
            <button
              type="button"
              onClick={() => {
                setInspectorTab('authorship');
                document.getElementById('workspace')?.scrollIntoView({ behavior: 'smooth' });
              }}
              className="hover:text-[var(--color-ink)] transition-colors cursor-pointer"
            >
              Авторство
            </button>
            <a href="/dashboard" className="hover:text-[var(--color-ink)] transition-colors">
              Мониторинг
            </a>
            <button
              type="button"
              onClick={() => pricingDialogRef.current?.showModal()}
              className="hover:text-[var(--color-ink)] transition-colors cursor-pointer"
            >
              Тарифы ₸
            </button>
          </nav>

          <div className="flex items-center gap-2 shrink-0">
            <ThemeToggle />
            <button
              type="button"
              onClick={handleDemoScan}
              disabled={isScanning}
              className="min-h-9 px-4 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-60 text-sm font-medium inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>Демо-аудит</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1">
        {/* Framed Editorial Hero matching prtner.ai/ */}
        <section aria-label="Введение" className="border-b border-[var(--color-line)]">
          <div className="max-w-[1160px] mx-auto border-x border-[var(--color-line)] px-6 sm:px-10 py-10 sm:py-14 relative overflow-hidden">
            {/* Subtle dithered monochrome mountain contour fading into bottom-right */}
            <svg
              aria-hidden="true"
              viewBox="0 0 420 180"
              className="hidden sm:block pointer-events-none select-none absolute right-0 bottom-0 w-[340px] md:w-[420px] opacity-[0.14] text-[var(--color-ink)]"
            >
              <defs>
                <pattern id="dither-dots" width="6" height="6" patternUnits="userSpaceOnUse">
                  <circle cx="1.5" cy="1.5" r="1" fill="currentColor" />
                </pattern>
              </defs>
              <path
                d="M10 180 L85 118 L135 140 L205 64 L268 112 L335 44 L420 116 L420 180 Z"
                fill="url(#dither-dots)"
              />
              <path
                d="M10 180 L85 118 L135 140 L205 64 L268 112 L335 44 L420 116"
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
              />
            </svg>

            <div className="max-w-3xl relative z-10 space-y-5">
              <h1 className="font-sans font-normal text-[clamp(2rem,4.3vw,3.45rem)] leading-[1.07] tracking-[-0.03em]">
                <span className="text-[var(--color-ink)] block">AI-агент безопасности кода,</span>
                <span className="text-[var(--color-muted-soft)] block">который работает по вашим правилам</span>
              </h1>

              <p className="text-base sm:text-[17px] text-[var(--color-body-text)] max-w-[60ch] leading-relaxed">
                Отвечает в чате по вашим уязвимостям, проверяет коммиты, утечки ИИН/секретов и
                подтверждает авторство репозитория внутри контура без облака{' '}
                <span className="font-mono text-xs px-1.5 py-0.5 rounded border border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-ink)] align-middle">
                  on-prem
                </span>
                .
              </p>

              <div className="pt-1 flex flex-wrap items-center gap-3">
                <a
                  href="#workspace"
                  onClick={() => setTimeout(() => document.querySelector<HTMLTextAreaElement>('#workspace textarea')?.focus(), 50)}
                  className="min-h-10 px-5 py-2 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white text-sm font-medium inline-flex items-center gap-2 transition-colors"
                >
                  <span>Открыть AI-чат</span>
                  <ArrowRight className="w-4 h-4" aria-hidden="true" />
                </a>
                <button
                  type="button"
                  onClick={() => {
                    setInspectorTab('authorship');
                    document.getElementById('workspace')?.scrollIntoView({ behavior: 'smooth' });
                  }}
                  className="min-h-10 px-5 py-2 rounded-full border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] bg-[var(--color-panel)] text-[var(--color-ink)] text-sm font-medium inline-flex items-center gap-2 transition-colors cursor-pointer"
                >
                  <Lock className="w-3.5 h-3.5 text-[#e94a32]" aria-hidden="true" />
                  <span>Проверить авторство</span>
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Interactive Dotted-Matrix Workspace (echoing prtner · inbound) */}
        <section id="workspace" aria-label="Рабочая область и AI-чат" className="border-b border-[var(--color-line)]">
          <div className="max-w-[1160px] mx-auto border-x border-[var(--color-line)] reg-frame">
            {/* Live Workspace Top Status Bar */}
            <div className="px-5 sm:px-8 py-3 border-b border-[var(--color-line)] bg-[var(--color-paper)] flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <span className="inline-flex items-center gap-2 text-[var(--color-ink)]">
                  <span
                    className={cn(
                      'w-2 h-2 rounded-full',
                      ollamaOnline ? 'bg-[#3fbf7f] animate-pulse' : 'bg-[#e8a33d]'
                    )}
                    aria-hidden="true"
                  />
                  <span>commit.guardian · live</span>
                </span>
                <span className="text-[var(--color-muted-soft)]">
                  {ollamaOnline ? `${ollamaModel} · 0 bytes external` : `appsec-engine · ${ollamaModel} standby`}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <input
                  id={zipInputId}
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
                  onClick={() => document.getElementById(zipInputId)?.click()}
                  className="min-h-8 px-3 py-1 rounded-lg border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] font-mono text-xs text-[var(--color-ink)] inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Загрузить .zip</span>
                </button>
              </div>
            </div>

            {/* Dotted Matrix Frame */}
            <div className="p-4 sm:p-8 prtner-dots space-y-5">
              {/* 4 Pipeline Selector Pills echoing prtner Direct / Comments / Mentions / Story replies */}
              <div className="space-y-2">
                <div className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                  IN · КОНТУР БЕЗОПАСНОСТИ · МОДУЛИ
                </div>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5" role="group" aria-label="Модули рабочей области">
                  {(
                    [
                      { id: 'overview', label: 'ОБЗОР И AI', count: `${messages.length}` },
                      { id: 'authorship', label: 'АВТОРСТВО', count: authorship.verified ? 'OK' : 'CHECK' },
                      { id: 'scanner', label: 'СКАНЕР И ЛОГИ', count: `${events.length}` },
                      { id: 'findings', label: 'ПАТЧИ И PDF', count: `${vulnerabilities}` },
                    ] as const
                  ).map((pill) => {
                    const active = inspectorTab === pill.id;
                    return (
                      <button
                        key={pill.id}
                        type="button"
                        aria-pressed={active}
                        onClick={() => setInspectorTab(pill.id)}
                        className={cn(
                          'min-h-10 px-3.5 py-2 rounded-xl border bg-[var(--color-paper)] flex items-center justify-between gap-2 font-mono text-xs transition-colors cursor-pointer',
                          active
                            ? 'border-[#e94a32] border-b-2 text-[var(--color-ink)]'
                            : 'border-[var(--color-line)] hover:border-[var(--color-line-strong)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                        )}
                      >
                        <span className="truncate tracking-wider">{pill.label}</span>
                        <span className="tabular-nums text-[var(--color-faint)]">{pill.count}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Unified Obsidian Workbench Card */}
              <div className="bg-[var(--color-paper)] border border-[var(--color-line)] rounded-2xl overflow-hidden shadow-[0_24px_48px_-24px_rgba(0,0,0,0.45)]">
                <div className="grid grid-cols-1 lg:grid-cols-12">
                  {/* Left: Spacious Native Dark AI Chat */}
                  <div className="lg:col-span-7 min-w-0">
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
                    />
                  </div>

                  {/* Right: Contextual Inspector Panel */}
                  <aside
                    aria-label="Инспектор аудита и авторства"
                    className="lg:col-span-5 border-t lg:border-t-0 lg:border-l border-[var(--color-line)] bg-[var(--color-paper)] p-5 flex flex-col justify-between gap-4 min-w-0"
                  >
                    {inspectorTab === 'authorship' ? (
                      <AuthorshipPanel
                        targetInput={verifyTarget}
                        onTargetInputChange={setVerifyTarget}
                        authorship={authorship}
                        onAuthorshipChange={setAuthorship}
                        requireOwnership={requireOwnership}
                        onRequireOwnershipChange={setRequireOwnership}
                        onAskAi={(q) => sendChatText(q)}
                      />
                    ) : inspectorTab === 'scanner' ? (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                            АУДИТ РЕПОЗИТОРИЯ
                          </span>
                          <span className="font-mono text-[11px] text-[var(--color-faint)]">
                            {auditAuthorshipLabel}
                          </span>
                        </div>

                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            startScan(repoScanUrl || verifyTarget);
                          }}
                          className="space-y-2"
                        >
                          <label htmlFor="cg-repo-url" className="visually-hidden">
                            GitHub URL для аудита
                          </label>
                          <input
                            id="cg-repo-url"
                            type="text"
                            value={repoScanUrl}
                            onChange={(e) => setRepoScanUrl(e.target.value)}
                            placeholder="https://github.com/owner/repo"
                            className="w-full min-h-9 px-3 py-1.5 rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] focus:border-[#e94a32] text-xs font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
                          />
                          <div className="flex gap-2">
                            <button
                              type="submit"
                              disabled={isScanning}
                              className="flex-1 min-h-9 px-3 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                            >
                              <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                              <span>{isScanning ? 'Сканирую...' : 'Сканировать URL'}</span>
                            </button>
                            <button
                              type="button"
                              onClick={handleDemoScan}
                              disabled={isScanning}
                              className="min-h-9 px-3 py-1.5 rounded-full border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] font-mono text-xs transition-colors cursor-pointer"
                            >
                              Демо KZ
                            </button>
                          </div>
                        </form>

                        <TerminalWindow events={events} targetLabel={activeTarget} />
                      </div>
                    ) : inspectorTab === 'findings' ? (
                      <div className="space-y-4 flex-1 flex flex-col min-h-0">
                        <SecurityScore
                          score={securityScore}
                          grade={grade}
                          elapsedTime={elapsedTime}
                          vulnerabilities={vulnerabilities}
                          isScanning={isScanning}
                          reportPdfUrl={reportPdfUrl}
                          reportMdUrl={reportMdUrl}
                        />

                        {findings.length > 0 ? (
                          <div
                            tabIndex={0}
                            role="region"
                            aria-labelledby="findings-caption"
                            className="table-wrapper cg-scroll border border-[var(--color-line)] rounded-xl bg-[var(--color-panel)] flex-1"
                          >
                            <table className="findings-table w-full table-fixed text-left text-xs">
                              <caption id="findings-caption" className="visually-hidden">
                                Обнаруженные уязвимости исходного кода
                              </caption>
                              <thead>
                                <tr className="text-[var(--color-muted-soft)] border-b border-[var(--color-line)] font-mono text-[10.5px] uppercase">
                                  <th scope="col" className="p-2.5 font-medium w-[74px]">Уровень</th>
                                  <th scope="col" className="p-2.5 font-medium">
                                    Уязвимость
                                    {appealedCount > 0 && (
                                      <span className="ml-1.5 text-[#3fbf7f] normal-case">
                                        ({activeFindingsCount} акт. · {appealedCount} FP)
                                      </span>
                                    )}
                                  </th>
                                  <th scope="col" className="p-2.5 font-medium w-[116px] text-right">Действия</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[var(--color-line)]">
                                {findings.map((f, idx) => {
                                  const fKey = makeFindingKey(f);
                                  const isAppealed = Boolean(appealedMap[fKey]);
                                  return (
                                    <tr
                                      key={`${f.id}-${idx}`}
                                      className={cn(
                                        'hover:bg-[var(--color-raised)]/60 transition-colors',
                                        isAppealed && 'opacity-55'
                                      )}
                                    >
                                      <td data-label="Уровень" className="p-2.5 align-top whitespace-nowrap">
                                        <span
                                          className={cn(
                                            'px-1.5 py-0.5 rounded font-mono text-[10px]',
                                            isAppealed
                                              ? 'bg-[#3fbf7f]/15 text-[#3fbf7f] border border-[#3fbf7f]/35'
                                              : SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO
                                          )}
                                        >
                                          {isAppealed ? 'FP' : f.severity}
                                        </span>
                                      </td>
                                      <th scope="row" className="p-2.5 font-normal align-top min-w-0">
                                        <div
                                          className={cn(
                                            'text-[var(--color-ink)] font-medium break-words leading-snug',
                                            isAppealed && 'line-through text-[var(--color-muted-soft)]'
                                          )}
                                        >
                                          {f.title}
                                        </div>
                                        <div className="font-mono text-[10.5px] text-[var(--color-muted-soft)] mt-0.5 break-all">
                                          {f.file_path}:{f.line_start || 1} · {formatCweShort(f.cwe)}
                                        </div>
                                      </th>
                                      <td data-label="Действия" className="p-2.5 align-top text-right whitespace-nowrap">
                                        <div className="inline-flex items-center justify-end gap-1">
                                          <button
                                            type="button"
                                            onClick={() => handleOpenRemediation(f)}
                                            className="min-h-7 px-2 py-1 rounded-full bg-[var(--color-raised)] hover:bg-[#e94a32] border border-[var(--color-line)] text-[var(--color-ink)] hover:text-white font-mono text-[10px] inline-flex items-center gap-1 transition-colors cursor-pointer"
                                          >
                                            <Wrench className="w-3 h-3" aria-hidden="true" />
                                            <span>Патч</span>
                                          </button>
                                          <button
                                            type="button"
                                            title={isAppealed ? 'Вернуть находку в активные' : 'Оспорить как ложное срабатывание (FP)'}
                                            onClick={() => handleToggleAppeal(f)}
                                            className={cn(
                                              'min-h-7 px-2 py-1 rounded-full border font-mono text-[10px] inline-flex items-center gap-1 transition-colors cursor-pointer',
                                              isAppealed
                                                ? 'border-[#3fbf7f]/50 text-[#3fbf7f] bg-[#3fbf7f]/10 hover:bg-[#3fbf7f]/20'
                                                : 'border-[var(--color-line)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] hover:border-[var(--color-line-strong)] bg-[var(--color-paper)]'
                                            )}
                                          >
                                            {isAppealed ? (
                                              <Undo2 className="w-3 h-3" aria-hidden="true" />
                                            ) : (
                                              <Flag className="w-3 h-3" aria-hidden="true" />
                                            )}
                                            <span>{isAppealed ? 'Верн.' : 'FP'}</span>
                                          </button>
                                        </div>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="flex-1 flex flex-col items-center justify-center text-center p-6 rounded-xl border border-dashed border-[var(--color-line)] text-xs font-mono text-[var(--color-muted-soft)]">
                            <p>Уязвимости появятся здесь после сканирования GitHub, ZIP или Демо KZ Fintech.</p>
                          </div>
                        )}
                      </div>
                    ) : (
                      /* Default Overview matching prtner drafting / routing card */
                      <div className="space-y-4 flex-1 flex flex-col justify-between">
                        <div className="space-y-4">
                          <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                            <span>DRAFT · TELEMETRY</span>
                            <span className={authorship.verified ? 'text-[#3fbf7f]' : 'text-[var(--color-faint)]'}>
                              {authorship.verified ? `OWNER @${authorship.actor}` : 'PUBLIC MODE'}
                            </span>
                          </div>

                          <SecurityScore
                            score={securityScore}
                            grade={grade}
                            elapsedTime={elapsedTime}
                            vulnerabilities={vulnerabilities}
                            isScanning={isScanning}
                            reportPdfUrl={reportPdfUrl}
                            reportMdUrl={reportMdUrl}
                          />

                          <MetricsDashboard
                            scannedFiles={scannedFiles}
                            totalFiles={totalFiles}
                            vulnerabilities={vulnerabilities}
                            elapsedTime={elapsedTime}
                            ollamaOnline={ollamaOnline}
                            ollamaModel={ollamaModel}
                            isScanning={isScanning}
                          />

                          {auditSummary && (
                            <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-3.5 text-xs text-[var(--color-body-text)] leading-relaxed">
                              <div className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)] mb-1">
                                ЗАКЛЮЧЕНИЕ АУДИТОРА
                              </div>
                              {auditSummary}
                            </div>
                          )}
                        </div>

                        <div className="grid grid-cols-2 gap-2 pt-2">
                          <button
                            type="button"
                            onClick={handleDemoScan}
                            disabled={isScanning}
                            className="min-h-9 px-3 py-2 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                          >
                            <Play className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Демо KZ</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => setInspectorTab('authorship')}
                            className="min-h-9 px-3 py-2 rounded-full border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] bg-[var(--color-panel)] text-[var(--color-ink)] font-mono text-xs inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                          >
                            <ShieldCheck className="w-3.5 h-3.5 text-[#3fbf7f]" aria-hidden="true" />
                            <span>Авторство</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </aside>
                </div>

                {/* Bottom 4-step Segmented Pipeline Progress Bar echoing SAVED | READ | DRAFT | ROUTE */}
                <div className="border-t border-[var(--color-line)] grid grid-cols-2 sm:grid-cols-4 font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)] bg-[var(--color-canvas)]">
                  {[
                    { step: 1, label: '01 АВТОРСТВО' },
                    { step: 2, label: '02 КЛОН / ZIP' },
                    { step: 3, label: '03 SAST + TAINT' },
                    { step: 4, label: '04 ИИ + PDF' },
                  ].map((s) => {
                    const active = pipelineStage >= s.step;
                    return (
                      <div
                        key={s.step}
                        className={cn(
                          'py-2.5 text-center border-r last:border-r-0 border-[var(--color-line)] border-b-2 transition-colors',
                          active ? 'border-b-[#e94a32] text-[var(--color-ink)]' : 'border-b-transparent'
                        )}
                      >
                        {s.label}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Financial Risk (CoAP RK) + Git Time Machine + Self-Healing With Proof */}
              {(financialRisk || ghostSecrets.length > 0 || healReport) && (
                <div id="guardian-insights" className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                      OUT · ФИНАНСОВЫЙ РИСК (КОАП РК) · МАШИНА ВРЕМЕНИ GIT · САМОИСЦЕЛЕНИЕ
                    </div>
                    {activeTarget === 'demo/kz-fintech-app' && (
                      <button
                        type="button"
                        disabled={isHealing || isScanning}
                        onClick={handleDemoHeal}
                        className="min-h-9 px-4 py-1.5 rounded-full bg-[#3fbf7f] hover:bg-[#34a96e] text-[#09120d] disabled:opacity-60 font-mono text-xs font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <HeartPulse className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>{isHealing ? 'Исцеляю и пересканирую...' : 'Исцелить автоматически (Self-Heal)'}</span>
                      </button>
                    )}
                  </div>

                  <div className={cn('grid grid-cols-1 gap-4', ghostSecrets.length > 0 && financialRisk && 'lg:grid-cols-12')}>
                    {financialRisk && (
                      <div className={ghostSecrets.length > 0 ? 'lg:col-span-7' : ''}>
                        <RiskCard risk={financialRisk} />
                      </div>
                    )}
                    {ghostSecrets.length > 0 && (
                      <div className={financialRisk ? 'lg:col-span-5' : ''}>
                        <GhostSecretsCard ghosts={ghostSecrets} />
                      </div>
                    )}
                  </div>

                  {healReport && <HealPanel report={healReport} />}
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Architecture & Case Band */}
        <section aria-label="On-premise архитектура" className="border-b border-[var(--color-line)]">
          <div className="max-w-[1160px] mx-auto border-x border-[var(--color-line)] reg-frame px-6 sm:px-10 py-12 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-6 space-y-3">
              <div className="font-mono text-xs uppercase tracking-wider text-[#e94a32]">
                ON-PREMISE · 94-V ФЗ И БАНКИ РК
              </div>
              <h2 className="font-sans font-normal text-2xl sm:text-3xl tracking-tight">
                Код и персональные данные не покидают ваш сервер
              </h2>
              <p className="text-sm sm:text-base text-[var(--color-body-text)] leading-relaxed max-w-[56ch]">
                Политика <code className="font-mono text-xs">.aegis.yml</code>, поиск утечек ИИН/БИН, проверка прав и
                подтверждение авторства перед аудитом, локальный инференс на Qwen2.5-Coder (Ollama GPU) и выгрузка
                PDF-отчётов в Telegram или PR.
              </p>
            </div>

            <div className="lg:col-span-6 bg-[var(--color-panel)] border border-[var(--color-line)] rounded-xl p-6 font-mono text-xs sm:text-sm space-y-2.5">
              <div className="flex items-baseline justify-between gap-2 pb-2 border-b border-[var(--color-line)]">
                <span className="text-[var(--color-muted-soft)]">CASE · FINTECH AUDIT</span>
                <span className="text-[#3fbf7f]">AIR-GAPPED</span>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-[var(--color-muted-soft)]">Сканеры</span>
                <span>Semgrep · Bandit · Taint AST</span>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-[var(--color-muted-soft)]">Проверка авторства</span>
                <span>Token · Commit Challenge · DNS TXT</span>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-[var(--color-muted-soft)]">Локальный AI</span>
                <span>{ollamaModel}</span>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-[var(--color-muted-soft)]">Облачный трафик</span>
                <span className="text-[#3fbf7f]">0 байт</span>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="max-w-[1160px] w-full mx-auto border-x border-[var(--color-line)] px-6 sm:px-10 py-8 flex flex-wrap items-center justify-between gap-4 font-mono text-xs text-[var(--color-muted-soft)]">
        <div className="flex items-center gap-2">
          <span>commit.guardian</span>
          <span>·</span>
          <span>On-Premise DevSecOps</span>
        </div>
        <div className="flex flex-wrap items-center gap-5">
          <a href="/dashboard" className="hover:text-[var(--color-ink)] transition-colors">
            /dashboard
          </a>
          <a href="/docs" className="hover:text-[var(--color-ink)] transition-colors">
            /docs API
          </a>
          <button
            type="button"
            onClick={() => pricingDialogRef.current?.showModal()}
            className="hover:text-[var(--color-ink)] transition-colors cursor-pointer"
          >
            Тарифы ₸
          </button>
          <span>Шрифт: Medeo OFL 1.1</span>
        </div>
      </footer>

      {/* Native <dialog>: AI Remediation & Optional PR */}
      <dialog
        ref={fixDialogRef}
        aria-labelledby="remediation-dialog-title"
        className="m-auto w-[min(92vw,740px)] rounded-2xl border border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-ink)] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-4 pb-3 border-b border-[var(--color-line)]">
          <div>
            <h2 id="remediation-dialog-title" className="font-sans text-xl font-medium">
              {selectedFinding?.title || 'Патч безопасности'}
            </h2>
            {selectedFinding && (
              <p className="text-xs font-mono text-[var(--color-muted-soft)] mt-1">
                {selectedFinding.file_path}:{selectedFinding.line_start || 1} · {formatCweShort(selectedFinding.cwe)}
              </p>
            )}
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть окно патча"
              className="min-h-9 min-w-9 p-1.5 rounded-full border border-[var(--color-line)] hover:border-[#e94a32] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer inline-flex items-center justify-center"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>

        {isFixing ? (
          <div className="py-8 text-sm font-mono text-[var(--color-muted-soft)]">
            Генерирую безопасный патч локальным движком...
          </div>
        ) : remediation ? (
          <div className="space-y-4 text-sm">
            <div>
              <div className="text-xs font-mono uppercase text-[var(--color-muted-soft)] mb-1">Причина и риск</div>
              <p className="text-[var(--color-ink)] leading-relaxed">{remediation.explanation_ru}</p>
              <p className="text-[#e94a32] text-xs mt-1">{remediation.impact_analysis}</p>
            </div>
            {remediation.remediation_steps.length > 0 && (
              <div>
                <div className="text-xs font-mono uppercase text-[var(--color-muted-soft)] mb-1">Как устранить</div>
                <ul className="list-disc pl-5 space-y-1 text-xs text-[var(--color-body-text)]">
                  {remediation.remediation_steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
            <div>
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                <div className="text-xs font-mono uppercase text-[var(--color-muted-soft)]">Безопасный код</div>
                {remediation.syntax_validated !== false && (
                  <span className="inline-flex items-center gap-1 font-mono text-[10.5px] px-2 py-0.5 rounded-full bg-[#3fbf7f]/15 text-[#3fbf7f] border border-[#3fbf7f]/35">
                    <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                    <span>AST ✓ Синтаксис проверен</span>
                  </span>
                )}
              </div>
              {remediation.validation_note && (
                <p className="text-[11px] font-mono text-[var(--color-muted-soft)] mb-1.5">
                  {remediation.validation_note}
                </p>
              )}
              <pre className="p-3 rounded-lg bg-[#0a0a0a] border border-[#232323] font-mono text-xs overflow-x-auto text-[#3fbf7f]">
                {remediation.fixed_code}
              </pre>
            </div>

            {authorship.canCreatePr && authorship.githubToken && activeTarget.includes('/') && !activeTarget.startsWith('demo/') && !activeTarget.startsWith('upload/') && (
              <div className="pt-2 border-t border-[var(--color-line)] flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  disabled={creatingPr}
                  onClick={handleCreatePR}
                  className="min-h-9 px-4 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>{creatingPr ? 'Создаю PR...' : 'Создать Pull Request'}</span>
                </button>
                {prStatus && <span className="font-mono text-xs text-[#3fbf7f] break-all">{prStatus}</span>}
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-[var(--color-muted-soft)]">
            {selectedFinding?.recommendation || selectedFinding?.description || 'Не удалось получить патч.'}
          </p>
        )}
      </dialog>

      {/* Native <dialog>: B2B On-Premise Pricing */}
      <dialog
        ref={pricingDialogRef}
        aria-labelledby="pricing-dialog-title"
        className="m-auto w-[min(92vw,780px)] rounded-2xl border border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-ink)] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 mb-5 pb-3 border-b border-[var(--color-line)]">
          <div>
            <h2 id="pricing-dialog-title" className="font-sans text-2xl font-medium">
              On-Premise архитектура и тарифы B2B
            </h2>
            <p className="text-xs text-[var(--color-muted-soft)] mt-1">
              Модель B2B-подписки внутри закрытого контура компании: исходный код и ПДн не покидают серверы заказчика.
            </p>
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть тарифы"
              className="min-h-9 min-w-9 p-1.5 rounded-full border border-[var(--color-line)] hover:border-[#e94a32] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer inline-flex items-center justify-center"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
            <div className="font-mono text-xs text-[#3fbf7f]">PILOT</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">0 ₸ / 14 дней</div>
            <p className="text-xs text-[var(--color-muted-soft)] mt-2 leading-relaxed">
              1–2 репозитория, Docker-развёртывание, алерты в Telegram и Compliance PDF для команды до 5 разработчиков.
            </p>
          </div>
          <div className="rounded-xl border border-[#e94a32] bg-[var(--color-panel)] p-4">
            <div className="font-mono text-xs text-[#e94a32]">TEAM ON-PREM</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">190 000 ₸ / мес</div>
            <p className="text-xs text-[var(--color-muted-soft)] mt-2 leading-relaxed">
              До 25 разработчиков, локальная Ollama, политики .aegis.yml (ИИН/ПДн), PR-фиксы и SIEM JSON-логи.
            </p>
          </div>
          <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-4">
            <div className="font-mono text-xs text-sky-400">ENTERPRISE GOV/FIN</div>
            <div className="text-xl font-medium font-mono mt-1 tabular-nums">от 650 000 ₸ / мес</div>
            <p className="text-xs text-[var(--color-muted-soft)] mt-2 leading-relaxed">
              Air-gapped контур без выхода в интернет, кастомные правила комплаенса банков и госсектора, SLA и выделенный GPU.
            </p>
          </div>
        </div>
      </dialog>
    </div>
  );
}

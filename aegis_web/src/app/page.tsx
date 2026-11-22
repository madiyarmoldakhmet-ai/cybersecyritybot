'use client';

import { FormEvent, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  CheckCircle2,
  ExternalLink,
  Flag,
  GitPullRequest,
  HeartPulse,
  Lock,
  PanelRightClose,
  PanelRightOpen,
  Terminal,
  Undo2,
  Wrench,
  X,
  Zap,
} from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { SecurityScore } from '@/components/SecurityScore';
import { AiCopilotChat, ChatAuditCard, ChatMessage } from '@/components/AiCopilotChat';
import { AuthorshipPanel, AuthorshipState } from '@/components/AuthorshipPanel';
import { CommitsReportsPanel, RepoCommit, ReportsFeedData } from '@/components/CommitsReportsPanel';
import { CompanionMood, OrcaCompanion } from '@/components/OrcaCompanion';
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

const WORKSPACE_STORAGE_KEY = 'commit_guardian_workspace_v2';

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

type InspectorTab = 'reports' | 'findings' | 'scanner' | 'authorship';

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
    'Привет! Я **Aegis Orca**, твоя локальная косатка-страж по безопасности коммитов (0 байт кода уходит в облако).\n' +
    'Нажми **«Демо-аудит»**, перетащи сюда свой `.zip` или подтверди свой репозиторий командой `/verify owner/repo` — просвечу код сонаром, поймаю утечки и сразу скину **PDF-отчёт** прямо сюда в чат.',
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

function formatCweShort(cwe: string[]): string {
  if (!cwe || cwe.length === 0) return '—';
  const m = cwe[0].match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : cwe[0].slice(0, 14);
}

function buildAuditChatCard(data: {
  repo_name?: string;
  commit_sha?: string;
  branch?: string;
  author?: string;
  total_findings?: number;
  vulnerabilities?: Finding[];
  findings?: Finding[];
  security_score?: number;
  grade?: string;
  summary?: string;
  report_pdf_url?: string | null;
  report_md_url?: string | null;
  financial_risk?: FinancialRisk | null;
  scan_result?: { duration_seconds?: number };
  duration_seconds?: number;
}): ChatAuditCard {
  const list = data.vulnerabilities || data.findings || [];
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of list) {
    const s = f.severity?.toUpperCase() as keyof typeof counts;
    if (s in counts) counts[s] += 1;
  }
  const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const topFindings = [...list]
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))
    .slice(0, 5)
    .map((f) => ({
      severity: f.severity,
      title: f.title,
      location: `${f.file_path}:${f.line_start || 1}`,
    }));
  const repoName = data.repo_name || 'workspace';
  return {
    repoName,
    commitSha: data.commit_sha || undefined,
    branch: data.branch || undefined,
    author: data.author || undefined,
    durationSeconds: data.scan_result?.duration_seconds ?? data.duration_seconds,
    score: typeof data.security_score === 'number' ? data.security_score : null,
    grade: data.grade ?? null,
    totalFindings: data.total_findings ?? list.length,
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    riskKzt: data.financial_risk?.total_kzt,
    summary: data.summary || '',
    pdfUrl: data.report_pdf_url ?? null,
    mdUrl: data.report_md_url ?? null,
    topFindings,
    canSelfHeal: repoName === 'demo/kz-fintech-app' && list.length > 0,
  };
}

export default function Home() {
  const prefersReducedMotion = useReducedMotion();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('reports');
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_ASSISTANT_MESSAGE]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [ownershipBlockedRepo, setOwnershipBlockedRepo] = useState<string | null>(null);

  // Live persisted commits & compliance reports feed (/api/v1/reports)
  const [reportsFeed, setReportsFeed] = useState<ReportsFeedData | null>(null);
  const [loadingFeed, setLoadingFeed] = useState(false);
  const [activeCommits, setActiveCommits] = useState<RepoCommit[]>([]);

  // Live backend & Ollama posture
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null);
  const [ollamaModel, setOllamaModel] = useState<string>('qwen2.5-coder:14b');

  // Authorship verification state (always strictly enforced for external GitHub repositories)
  const [verifyTarget, setVerifyTarget] = useState('https://github.com/madiyarmoldakhmet-ai/cybersecyritybot');
  const [authorship, setAuthorship] = useState<AuthorshipState>(EMPTY_AUTHORSHIP);
  const requireOwnership = true;
  const [repoScanUrl, setRepoScanUrl] = useState('');

  // Scan & audit state
  const [isScanning, setIsScanning] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
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

  const openDrawerTab = useCallback((tab: InspectorTab) => {
    setInspectorTab(tab);
    setDrawerOpen(true);
  }, []);

  const refreshReportsFeed = useCallback(async () => {
    setLoadingFeed(true);
    try {
      const res = await fetch('/api/v1/reports?limit=25', { cache: 'no-store' });
      if (res.ok) {
        setReportsFeed(await res.json());
      }
    } catch {
      // Keep previous feed cleanly
    } finally {
      setLoadingFeed(false);
    }
  }, []);

  useEffect(() => {
    refreshReportsFeed();
  }, [refreshReportsFeed]);

  // Close drawer cleanly on Escape
  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') setDrawerOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerOpen]);

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

  const ghostCommitShas = useMemo(() => {
    const set = new Set<string>();
    for (const g of ghostSecrets) {
      if (g.introduced?.short) set.add(g.introduced.short);
      if (g.removed?.short) set.add(g.removed.short);
    }
    return set;
  }, [ghostSecrets]);

  const activeFindingsCount = useMemo(
    () => findings.filter((f) => !appealedMap[makeFindingKey(f)]).length,
    [findings, appealedMap]
  );
  const appealedCount = Object.keys(appealedMap).length;

  // Dialog for AI Remediation & PR
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
        if (data.type === 'authorship' && data.proof_token) {
          setOwnershipBlockedRepo(null);
          setAuthorship((prev) => ({
            ...prev,
            verified: true,
            target: data.target || prev.target,
            targetType: 'github',
            method: data.method || 'commit_challenge',
            actor: data.actor || 'verified-author',
            role: data.role || 'CommitVerified',
            message: data.message || `Авторство ${data.target} подтверждено.`,
            proofToken: data.proof_token,
          }));
        } else if (data.type === 'action' && data.action === 'SCAN') {
          setIsTyping(false);
          setMessages((prev) => prev.filter((m) => m.id !== 'streaming'));
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
              if (!last.content.trim()) {
                return prev.slice(0, -1);
              }
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
          if (Array.isArray(saved.activeCommits)) setActiveCommits(saved.activeCommits);
          if (saved.reportPdfUrl) setReportPdfUrl(saved.reportPdfUrl);
          if (saved.reportMdUrl) setReportMdUrl(saved.reportMdUrl);
          if (saved.financialRisk) setFinancialRisk(saved.financialRisk);
          if (saved.healReport) setHealReport(saved.healReport);
          if (saved.appealedMap && typeof saved.appealedMap === 'object') setAppealedMap(saved.appealedMap);
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
          activeCommits,
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
    activeCommits,
    reportPdfUrl,
    reportMdUrl,
    financialRisk,
    healReport,
    appealedMap,
  ]);

  const resetScanState = (targetLabel: string) => {
    setOwnershipBlockedRepo(null);
    setEvents([]);
    setFindings([]);
    setVulnerabilities(0);
    setElapsedTime(0);
    setSecurityScore(null);
    setGrade(null);
    setAuditSummary('');
    setActiveCommits([]);
    setReportPdfUrl(null);
    setReportMdUrl(null);
    setFinancialRisk(null);
    setHealReport(null);
    setAppealedMap({});
    setActiveTarget(targetLabel);
    setAuditAuthorshipLabel(authorship.verified ? `Подтверждён (${authorship.role})` : 'Локально / Read-Only');
    setIsScanning(true);

    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setElapsedTime((prev) => +(prev + 0.2).toFixed(1));
    }, 200);
  };

  const applyCompletedPayload = (data: {
    repo_name?: string;
    commit_sha?: string;
    branch?: string;
    author?: string;
    commits?: RepoCommit[];
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
    if (data.repo_name) setActiveTarget(data.repo_name);
    if (typeof data.security_score === 'number') setSecurityScore(data.security_score);
    if (data.grade) setGrade(data.grade);
    if (data.summary) setAuditSummary(data.summary);
    if (Array.isArray(data.commits)) setActiveCommits(data.commits);
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
    refreshReportsFeed();

    setEvents((prev) => [
      ...prev.slice(-190),
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
          if (data.verified_authorship?.proof_token) {
            const va = data.verified_authorship;
            setOwnershipBlockedRepo(null);
            setAuthorship((prev) => ({
              ...prev,
              verified: true,
              target: va.target || prev.target,
              targetType: 'github',
              method: va.method || 'commit_challenge',
              actor: va.actor || 'verified-author',
              role: va.role || 'CommitVerified',
              message: va.message || `Авторство ${va.target} подтверждено.`,
              proofToken: va.proof_token,
            }));
          }
          if (data.action === 'SCAN' && data.github_url) {
            setMessages((prev) => prev.filter((m) => m.id !== 'streaming'));
            startScanRef.current(data.github_url);
            return;
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
    setOwnershipBlockedRepo(null);
    if (chatWsRef.current && chatWsRef.current.readyState === WebSocket.OPEN) {
      chatWsRef.current.send(JSON.stringify({ reset: true }));
    }
  };

  const handleDemoScan = async () => {
    resetScanState('demo/kz-fintech-app');
    const now = formatNowTime();
    setMessages((prev) => [
      ...prev.filter((m) => m.id !== 'scan-status'),
      { id: `${Date.now()}`, role: 'user', content: 'Запусти демо-аудит KZ Fintech', timestamp: now },
      { id: 'scan-status', role: 'assistant', content: 'Клонирую историю коммитов и запускаю локальный аудит (SAST + Taint + Secrets + Git Time Machine)...', timestamp: now },
    ]);
    setEvents([{ event_type: 'ScanStarted', message: 'Инициализация on-premise движка Commit Guardian...' }]);

    try {
      const res = await fetch('/api/scan/demo', { method: 'POST' });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'scan-status');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content: 'Аудит завершён — официальный Compliance-отчёт и сводка по коммитам готовы:',
              auditCard: buildAuditChatCard(data),
              timestamp: formatNowTime(),
            },
          ];
        }
        return [...filtered, { id: `${Date.now()}`, role: 'assistant', content: `Ошибка демо-скана: ${data.error}`, timestamp: formatNowTime() }];
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
        ...prev.filter((m) => m.id !== 'scan-status'),
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
      ...prev.filter((m) => m.id !== 'scan-status'),
      { id: `${Date.now()}`, role: 'user', content: `Проверь архив \`${file.name}\``, timestamp: now },
      { id: 'scan-status', role: 'assistant', content: 'Распаковка и локальный анализ (код будет удалён сразу после проверки)...', timestamp: now },
    ]);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/scan/upload', { method: 'POST', body: formData });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'scan-status');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content: 'Аудит ZIP-архива завершён, исходный код удалён с сервера:',
              auditCard: buildAuditChatCard(data),
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
        ...prev.filter((m) => m.id !== 'scan-status'),
        { id: `${Date.now()}`, role: 'assistant', content: `Ошибка сети при загрузке: ${err}`, timestamp: formatNowTime() },
      ]);
    }
  };

  const runRepoScanHttpFallback = async (clean: string) => {
    try {
      const res = await fetch('/api/scan/repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          github_url: clean,
          github_token: authorship.githubToken || undefined,
          proof_token: authorship.proofToken || undefined,
          require_ownership: requireOwnership,
        }),
      });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'scan-status');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content: 'Аудит репозитория и коммитов завершён, копия кода удалена с сервера:',
              auditCard: buildAuditChatCard(data),
              timestamp: formatNowTime(),
            },
          ];
        }
        return [
          ...filtered,
          { id: `${Date.now()}`, role: 'assistant', content: `⛔ ${data.error || 'Не удалось выполнить скан репозитория.'}`, timestamp: formatNowTime() },
        ];
      });
      if (res.ok) {
        applyCompletedPayload(data);
      } else {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        if (data.code === 'OWNERSHIP_REQUIRED') {
          setOwnershipBlockedRepo(data.repo_name || clean);
          if (data.repo_name) setVerifyTarget(data.repo_name);
          openDrawerTab('authorship');
        }
      }
    } catch (err) {
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'scan-status'),
        { id: `${Date.now()}`, role: 'assistant', content: `⛔ Ошибка сети при сканировании: ${err}`, timestamp: formatNowTime() },
      ]);
    }
  };

  const startScan = (repoUrl: string) => {
    const clean = repoUrl.trim();
    if (!clean) return;
    setRepoScanUrl(clean);
    setVerifyTarget(clean);
    resetScanState(clean);

    const now = formatNowTime();
    setMessages((prev) => [
      ...prev.filter((m) => m.id !== 'scan-status' && m.id !== 'streaming'),
      { id: 'scan-status', role: 'assistant', content: `Проверяю авторство и запускаю аудит \`${clean}\`...`, timestamp: now },
    ]);

    let finished = false;
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
        finished = true;
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== 'scan-status'),
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: 'Аудит репозитория и коммитов завершён, копия кода удалена с сервера:',
            auditCard: buildAuditChatCard(data),
            timestamp: formatNowTime(),
          },
        ]);
        applyCompletedPayload(data);
        return;
      }
      setEvents((prev) => [...prev.slice(-199), data]);
      if (data.event_type === 'VulnerabilityFound') {
        setVulnerabilities((prev) => prev + 1);
      } else if (data.event_type === 'SystemError') {
        finished = true;
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        if (data.code === 'OWNERSHIP_REQUIRED') {
          setOwnershipBlockedRepo(data.repo_name || clean);
          if (data.repo_name) setVerifyTarget(data.repo_name);
          openDrawerTab('authorship');
        }
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== 'scan-status'),
          { id: `${Date.now()}`, role: 'assistant', content: `⛔ ${data.message}`, timestamp: formatNowTime() },
        ]);
      } else if (data.event_type === 'ScanCompleted') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };

    ws.onerror = () => {
      if (!finished) {
        finished = true;
        ws.close();
        runRepoScanHttpFallback(clean);
      }
    };

    ws.onclose = () => {
      if (!finished) {
        finished = true;
        runRepoScanHttpFallback(clean);
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
      ...prev.filter((m) => m.id !== 'scan-status'),
      { id: `${Date.now()}`, role: 'user', content: 'Запусти самоисцеление с доказательством (Self-Heal)', timestamp: now },
      { id: 'scan-status', role: 'assistant', content: 'Патчу копию кода через AST → ast.parse() → пересканирую песочницу...', timestamp: now },
    ]);
    try {
      const res = await fetch('/api/scan/demo/heal', { method: 'POST' });
      const data = await res.json();
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'scan-status');
        if (res.ok) {
          return [
            ...filtered,
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content:
                `Готово! Самоисцеление подтверждено пересканированием: Score **${data.before_score} (${data.before_grade}) → ${data.after_score} (${data.after_grade})**, ` +
                `находки **${data.before_findings} → ${data.after_findings}**, риск **${formatKzt(data.before_risk_kzt)} → ${formatKzt(data.after_risk_kzt)}**. ` +
                `Все проверенные diffs открыла в панели справа.`,
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
        setSecurityScore(data.after_score);
        setGrade(data.after_grade);
        openDrawerTab('findings');
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'scan-status'),
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
          refreshReportsFeed();
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
        refreshReportsFeed();
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

  // Compute live Aegis-chan mood & contextual speech
  const companionMood: CompanionMood = useMemo(() => {
    if (isScanning || isHealing) return 'scanning';
    if (isTyping) return 'thinking';
    if (ownershipBlockedRepo) return 'blocked';
    if (healReport) return 'happy';
    if (securityScore !== null) {
      return securityScore >= 70 ? 'happy' : 'alert';
    }
    if (authorship.verified) return 'happy';
    return 'idle';
  }, [isScanning, isHealing, isTyping, ownershipBlockedRepo, healReport, securityScore, authorship.verified]);

  const companionSpeech = useMemo(() => {
    if (isHealing) return 'Патчу уязвимый код, прогоняю ast.parse() и пересканирую песочницу…';
    if (isScanning) return `Просвечиваю ${activeTarget || 'репозиторий'} сонаром: AST, Taint, секреты и Git-история…`;
    if (isTyping) return 'Пингую локальный движок — разбираю твой вопрос…';
    if (ownershipBlockedRepo) {
      return `Стоп! Чужой репозиторий ${ownershipBlockedRepo} без подтверждения авторства не пропущу. Пройди /verify справа!`;
    }
    if (healReport) {
      return `Сожрал ${healReport.fixed_count} уязвимостей: Score ${healReport.before_score} → ${healReport.after_score} (${healReport.after_grade}). Проверенные diffs уже в панели «Находки»!`;
    }
    if (securityScore !== null && activeFindingsCount > 0) {
      return securityScore < 70
        ? `Тревога! Поймал ${activeFindingsCount} проблем в ${activeTarget} (Score ${securityScore}/100). Открой «Находки» или жми Self-Heal!`
        : `Проверил ${activeTarget}: Score ${securityScore}/100 (${grade}). Есть ${activeFindingsCount} мелких замечаний — по критике чисто.`;
    }
    if (securityScore !== null && activeFindingsCount === 0) {
      return `Вода чиста в ${activeTarget}! Score ${securityScore}/100 (${grade}) — ни одной активной угрозы.`;
    }
    if (authorship.verified) {
      return `Авторство ${authorship.target} подтверждено! Кидай ссылку в чат — сразу проверю.`;
    }
    return 'На патруле! Жми «Демо-аудит», кидай .zip или вводи /verify owner/repo для своего проекта.';
  }, [
    isHealing,
    isScanning,
    isTyping,
    activeTarget,
    ownershipBlockedRepo,
    healReport,
    securityScore,
    activeFindingsCount,
    grade,
    authorship.verified,
    authorship.target,
  ]);

  const canSelfHealDemo = activeTarget === 'demo/kz-fintech-app' && findings.length > 0 && !healReport;

  return (
    <div className="h-dvh w-full overflow-hidden bg-[var(--color-canvas)] text-[var(--color-ink)] font-sans flex flex-col">
      <a href="#chat-workspace" className="skip-link visually-hidden">
        Перейти к чату с Aegis Orca
      </a>

      {/* Hidden global ZIP input shared by companion & chat */}
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

      {/* Single Compact 52px App Top Bar (content-first, <12% viewport height) */}
      <header className="h-[52px] shrink-0 border-b border-[var(--color-line)] bg-[var(--color-paper)] px-4 sm:px-5 flex items-center justify-between gap-3 z-20">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2 shrink-0">
            <span className="grid grid-cols-2 gap-0.5 w-3.5 h-3.5 shrink-0" aria-hidden="true">
              <span className="bg-[#e94a32]" />
              <span className="bg-[var(--color-ink)]" />
              <span className="bg-[var(--color-ink)]" />
              <span className="bg-[var(--color-ink)] opacity-45" />
            </span>
            <span className="font-sans text-[15px] font-medium tracking-tight">
              commit<span className="text-[#e94a32]">.</span>guardian
            </span>
          </div>
          <span className="hidden md:inline-flex items-center gap-1.5 font-mono text-[10.5px] px-2 py-0.5 rounded-full border border-[var(--color-line)] bg-[var(--color-panel)] text-[var(--color-muted-soft)]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#3fbf7f]" aria-hidden="true" />
            <span>on-prem · 0 bytes cloud</span>
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <a
            href="/dashboard"
            className="hidden sm:inline-flex items-center gap-1 min-h-8 px-2.5 rounded-lg border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11px] transition-colors"
          >
            <span>/dashboard</span>
            <ExternalLink className="w-3 h-3" aria-hidden="true" />
          </a>

          <button
            type="button"
            onClick={() => {
              if (drawerOpen) {
                setDrawerOpen(false);
              } else {
                openDrawerTab(findings.length > 0 ? 'findings' : 'reports');
              }
            }}
            className={cn(
              'min-h-8 px-2.5 rounded-lg border font-mono text-[11px] inline-flex items-center gap-1.5 transition-colors cursor-pointer',
              drawerOpen
                ? 'border-[#e94a32] bg-[#e94a32]/12 text-[var(--color-ink)]'
                : 'border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
            )}
          >
            {drawerOpen ? (
              <PanelRightClose className="w-3.5 h-3.5" aria-hidden="true" />
            ) : (
              <PanelRightOpen className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            <span className="hidden sm:inline">Инспектор</span>
          </button>

          <ThemeToggle />

          <button
            type="button"
            onClick={handleDemoScan}
            disabled={isScanning}
            className="min-h-8 px-3.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-55 text-xs font-medium inline-flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Zap className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Демо-аудит</span>
          </button>
        </div>
      </header>

      {/* Pure Full-Viewport Companion + Chat Shell */}
      <main id="chat-workspace" className="flex-1 min-h-0 flex flex-col lg:flex-row relative overflow-hidden">
        {/* Left: Live Animated Cyber-Orca Companion */}
        <div className="lg:w-[320px] xl:w-[348px] lg:h-full shrink-0 flex flex-col">
          <OrcaCompanion
            mood={companionMood}
            speech={companionSpeech}
            isScanning={isScanning}
            isHealing={isHealing}
            elapsedTime={elapsedTime}
            securityScore={securityScore}
            grade={grade}
            findingsCount={activeFindingsCount}
            reportsCount={reportsFeed?.total_scans ?? 0}
            authorshipVerified={authorship.verified}
            canSelfHeal={canSelfHealDemo}
            onDemoScan={handleDemoScan}
            onTriggerSelfHeal={handleDemoHeal}
            onUploadZipClick={() => document.getElementById(zipInputId)?.click()}
            onOpenDrawer={openDrawerTab}
          />
        </div>

        {/* Center: Full-Height Pure Chat Stream */}
        <div className="flex-1 min-w-0 min-h-0 flex flex-col">
          <AiCopilotChat
            messages={messages}
            input={input}
            onInputChange={setInput}
            onSubmit={handleSendMessage}
            onQuickPrompt={(prompt) => sendChatText(prompt)}
            onResetChat={handleResetChat}
            onUploadZip={handleZipUpload}
            onTriggerSelfHeal={handleDemoHeal}
            onOpenFindingsDrawer={() => openDrawerTab('findings')}
            isHealing={isHealing}
            isTyping={isTyping}
            isScanning={isScanning}
            ollamaOnline={ollamaOnline}
            ollamaModel={ollamaModel}
            activeTarget={activeTarget}
          />
        </div>

        {/* Right: On-Demand Collapsible Inspector Drawer (Reports / Findings+Risk+SelfHeal / Logs / Authorship) */}
        <AnimatePresence>
          {drawerOpen && (
            <motion.aside
              aria-label="Инспектор аудита, коммитов и авторства"
              initial={prefersReducedMotion ? { opacity: 1 } : { opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={prefersReducedMotion ? { opacity: 0 } : { opacity: 0, x: 24 }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
              className="fixed inset-y-[52px] right-0 z-30 w-full max-w-[440px] lg:static lg:inset-auto lg:w-[410px] xl:w-[440px] lg:h-full border-l border-[var(--color-line)] bg-[var(--color-paper)] flex flex-col min-h-0 shadow-2xl lg:shadow-none shrink-0"
            >
              {/* Drawer Tabs + Close */}
              <div className="px-3 py-2.5 border-b border-[var(--color-line)] flex items-center justify-between gap-2 shrink-0">
                <div className="grid grid-cols-4 gap-1 flex-1 min-w-0" role="tablist" aria-label="Разделы инспектора">
                  {(
                    [
                      { id: 'reports', label: 'Отчёты', badge: `${reportsFeed?.total_scans ?? 0}` },
                      { id: 'findings', label: 'Находки', badge: `${activeFindingsCount}` },
                      { id: 'authorship', label: 'Автор', badge: authorship.verified ? 'OK' : '!' },
                      { id: 'scanner', label: 'Логи', badge: `${events.length}` },
                    ] as const
                  ).map((tab) => {
                    const active = inspectorTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        aria-selected={active}
                        onClick={() => setInspectorTab(tab.id)}
                        className={cn(
                          'min-h-8 px-2 py-1 rounded-lg border font-mono text-[10.5px] flex items-center justify-center gap-1 transition-colors cursor-pointer truncate',
                          active
                            ? 'border-[#e94a32] bg-[#e94a32]/12 text-[var(--color-ink)] font-medium'
                            : 'border-[var(--color-line)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                        )}
                      >
                        <span className="truncate">{tab.label}</span>
                        <span className="tabular-nums opacity-70">{tab.badge}</span>
                      </button>
                    );
                  })}
                </div>

                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  aria-label="Скрыть панель инспектора"
                  className="min-h-8 min-w-8 rounded-lg border border-[var(--color-line)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] flex items-center justify-center shrink-0 cursor-pointer transition-colors"
                >
                  <X className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              </div>

              {/* Drawer Scrollable Body */}
              <div className="cg-scroll flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-4">
                {inspectorTab === 'authorship' ? (
                  <AuthorshipPanel
                    targetInput={verifyTarget}
                    onTargetInputChange={setVerifyTarget}
                    authorship={authorship}
                    onAuthorshipChange={(next) => {
                      setAuthorship(next);
                      if (next.verified) setOwnershipBlockedRepo(null);
                    }}
                    onAskAi={(q) => sendChatText(q)}
                  />
                ) : inspectorTab === 'scanner' ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                        АУДИТ СВОЕГО РЕПОЗИТОРИЯ
                      </span>
                      <span className="font-mono text-[11px] text-[var(--color-faint)]">
                        {auditAuthorshipLabel}
                      </span>
                    </div>

                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        if (repoScanUrl.trim()) startScan(repoScanUrl);
                      }}
                      className="space-y-2"
                    >
                      <label htmlFor="cg-repo-url" className="visually-hidden">
                        GitHub URL репозитория для локального аудита
                      </label>
                      <input
                        id="cg-repo-url"
                        type="text"
                        value={repoScanUrl}
                        onChange={(e) => setRepoScanUrl(e.target.value)}
                        placeholder="https://github.com/owner/repo"
                        disabled={isScanning}
                        className="w-full min-h-9 px-3 py-1.5 rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] focus:border-[#e94a32] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
                      />
                      <div className="flex gap-2">
                        <button
                          type="submit"
                          disabled={isScanning || !repoScanUrl.trim()}
                          className="flex-1 min-h-9 px-3 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-45 font-mono text-xs inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>{isScanning ? 'Сканирую…' : 'Сканировать URL'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleDemoScan}
                          disabled={isScanning}
                          className="min-h-9 px-3 py-1.5 rounded-full border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] font-mono text-xs text-[var(--color-ink)] transition-colors cursor-pointer"
                        >
                          Демо KZ
                        </button>
                      </div>
                    </form>

                    <TerminalWindow
                      events={events}
                      targetLabel={activeTarget || repoScanUrl}
                    />
                  </div>
                ) : inspectorTab === 'findings' ? (
                  <div className="space-y-4">
                    <SecurityScore
                      score={securityScore}
                      grade={grade}
                      vulnerabilities={activeFindingsCount}
                      isScanning={isScanning}
                      elapsedTime={elapsedTime}
                      reportPdfUrl={reportPdfUrl}
                      reportMdUrl={reportMdUrl}
                    />

                    {canSelfHealDemo && (
                      <button
                        type="button"
                        disabled={isHealing}
                        onClick={handleDemoHeal}
                        className="w-full min-h-10 px-4 py-2 rounded-xl bg-[#3fbf7f] hover:bg-[#34a96e] text-[#09120d] disabled:opacity-60 font-mono text-xs font-semibold inline-flex items-center justify-center gap-2 transition-colors cursor-pointer"
                      >
                        <HeartPulse className="w-4 h-4" aria-hidden="true" />
                        <span>{isHealing ? 'Исцеляю и пересканирую…' : 'Исцелить автоматически (Self-Heal)'}</span>
                      </button>
                    )}

                    {healReport && <HealPanel report={healReport} />}
                    {financialRisk && <RiskCard risk={financialRisk} />}
                    {ghostSecrets.length > 0 && <GhostSecretsCard ghosts={ghostSecrets} />}

                    {auditSummary && (
                      <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-3 text-xs leading-relaxed text-[var(--color-body-text)]">
                        <span className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)] mr-1.5">
                          Заключение:
                        </span>
                        {auditSummary}
                      </div>
                    )}

                    {appealedCount > 0 && (
                      <div className="rounded-lg border border-[#3fbf7f]/35 bg-[#3fbf7f]/10 px-3 py-1.5 font-mono text-[11px] text-[#3fbf7f] flex items-center justify-between gap-2">
                        <span>Оспорено FP: {appealedCount}</span>
                        <span>Score пересчитан</span>
                      </div>
                    )}

                    {findings.length > 0 ? (
                      <div className="space-y-2">
                        {findings.map((f, idx) => {
                          const fKey = makeFindingKey(f);
                          const isAppealed = Boolean(appealedMap[fKey]);
                          return (
                            <div
                              key={`${f.id}-${idx}`}
                              className={cn(
                                'rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-3 space-y-2',
                                isAppealed && 'opacity-55'
                              )}
                            >
                              <div className="flex items-start justify-between gap-2">
                                <span className={cn('font-mono text-[10px] px-2 py-0.5 rounded shrink-0', SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO)}>
                                  {f.severity}
                                </span>
                                <span className="font-mono text-[10.5px] text-[var(--color-muted-soft)]">
                                  {formatCweShort(f.cwe)}
                                </span>
                              </div>
                              <div className={cn('text-xs font-medium text-[var(--color-ink)] leading-snug', isAppealed && 'line-through')}>
                                {f.title}
                              </div>
                              <div className="font-mono text-[11px] text-[var(--color-muted-soft)] truncate">
                                {f.file_path}:{f.line_start || 1}
                              </div>
                              <div className="flex items-center gap-1.5 pt-0.5">
                                <button
                                  type="button"
                                  onClick={() => handleOpenRemediation(f)}
                                  className="min-h-7 px-2.5 py-1 rounded-md border border-[var(--color-line-strong)] hover:border-[#e94a32] bg-[var(--color-paper)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors"
                                >
                                  <Wrench className="w-3 h-3" aria-hidden="true" />
                                  <span>Патч</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleToggleAppeal(f)}
                                  className={cn(
                                    'min-h-7 px-2.5 py-1 rounded-md border font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors',
                                    isAppealed
                                      ? 'border-[#3fbf7f]/45 bg-[#3fbf7f]/15 text-[#3fbf7f]'
                                      : 'border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                                  )}
                                >
                                  {isAppealed ? <Undo2 className="w-3 h-3" aria-hidden="true" /> : <Flag className="w-3 h-3" aria-hidden="true" />}
                                  <span>{isAppealed ? 'Верн.' : 'FP'}</span>
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-dashed border-[var(--color-line-strong)] p-5 text-center space-y-2">
                        <p className="font-mono text-xs text-[var(--color-muted-soft)]">
                          Находок пока нет — запусти «Демо-аудит» или проверь свой репозиторий.
                        </p>
                        <button
                          type="button"
                          onClick={handleDemoScan}
                          disabled={isScanning}
                          className="min-h-8 px-4 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs cursor-pointer transition-colors"
                        >
                          Запустить Демо-аудит →
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <CommitsReportsPanel
                    feed={reportsFeed}
                    loadingFeed={loadingFeed}
                    onRefreshFeed={refreshReportsFeed}
                    activeCommits={activeCommits}
                    activeRepoName={activeTarget}
                    ghostCommitShas={ghostCommitShas}
                    isScanning={isScanning}
                    onScanRepo={(url) => startScan(url)}
                    onDemoScan={handleDemoScan}
                  />
                )}
              </div>

              {/* Drawer Bottom Privacy Note */}
              <div className="px-4 py-2 border-t border-[var(--color-line)] font-mono text-[10.5px] text-[var(--color-faint)] flex items-center justify-between gap-2 shrink-0">
                <span className="inline-flex items-center gap-1">
                  <Lock className="w-3 h-3 text-[#e94a32]" aria-hidden="true" />
                  <span>Строгое авторство · локальный контур</span>
                </span>
                <span>{vulnerabilities} нах.</span>
              </div>
            </motion.aside>
          )}
        </AnimatePresence>
      </main>

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
    </div>
  );
}

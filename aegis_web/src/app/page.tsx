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
import {
  AiCopilotChat,
  ChatAuditCard,
  ChatCommitCard,
  ChatMessage,
  ChatVerifyCard,
  SystemAnalysisSummary,
} from '@/components/AiCopilotChat';
import { AiModelSwitcher } from '@/components/AiModelSwitcher';
import { AuthorshipPanel, AuthorshipState, PendingVerifyChallenge } from '@/components/AuthorshipPanel';
import { CommitsReportsPanel, RepoCommit, ReportsFeedData } from '@/components/CommitsReportsPanel';
import { CompanionMood, OrcaCompanion } from '@/components/OrcaCompanion';
import { ChristmasLightsGarland, ChristmasTreeBadge } from '@/components/ChristmasDecor';
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
  CRITICAL: 'bg-[#e94a32]/20 text-[#ff8573] border-2 border-[#e94a32]',
  HIGH: 'bg-orange-500/20 text-orange-300 border-2 border-orange-500/70',
  MEDIUM: 'bg-[#f0b541]/20 text-[#ffe79e] border-2 border-[#f0b541]/70',
  LOW: 'bg-[#2da890]/20 text-[#56d4b2] border-2 border-[#2da890]',
  INFO: 'bg-[var(--color-raised)] text-[var(--color-muted-soft)] border-2 border-[var(--color-line)]',
};

const INITIAL_ASSISTANT_MESSAGE: ChatMessage = {
  id: 'welcome-1',
  role: 'assistant',
  content:
    'С наступающими праздниками! 🎄 Я **Aegis Orca**, твоя локальная говорящая косатка-страж (0 байт кода уходит в облако).\n' +
    'Просто вставь ссылку на свой GitHub — я выдам кнопку подтверждения в 1 клик, сама всё проверю и сразу запущу аудит! Или жми **«Демо-аудит»** / перетащи сюда `.zip`.',
  timestamp: 'Сегодня',
};

function summarizeSpeechLine(markdown: string): string {
  const plain = markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/^#{1,4}\s+/gm, '')
    .replace(/[*_`]/g, '')
    .replace(/⛔|✅|🔐/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!plain) return '';
  const firstSentence = plain.match(/^[^.!?]+[.!?]/)?.[0] || plain;
  const trimmed = firstSentence.length >= 24 ? firstSentence : plain;
  return trimmed.length > 150 ? `${trimmed.slice(0, 147).trim()}…` : trimmed;
}

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
  system_analysis?: SystemAnalysisSummary | null;
  scan_result?: { duration_seconds?: number; system_analysis?: SystemAnalysisSummary | null };
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
  const isRealRepo = repoName !== 'demo/kz-fintech-app' && !repoName.startsWith('upload/') && repoName.includes('/');
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
    systemAnalysis: data.system_analysis ?? data.scan_result?.system_analysis ?? null,
    canSelfHeal: (repoName === 'demo/kz-fintech-app' || isRealRepo) && list.length > 0,
    isRealRepo,
  };
}

export default function Home() {
  const prefersReducedMotion = useReducedMotion();
  const [motionPaused, setMotionPaused] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('reports');
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_ASSISTANT_MESSAGE]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [ownershipBlockedRepo, setOwnershipBlockedRepo] = useState<string | null>(null);
  const [pendingVerify, setPendingVerify] = useState<(PendingVerifyChallenge & { checks: number }) | null>(null);
  const [isCheckingVerify, setIsCheckingVerify] = useState(false);
  const [orcaChatReply, setOrcaChatReply] = useState<string>('');

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
  const [systemAnalysis, setSystemAnalysis] = useState<SystemAnalysisSummary | null>(null);
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
  const wsPendingRef = useRef<{ message: string; scan_context?: Record<string, unknown> } | null>(null);
  const wsWatchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const httpChatFallbackRef = useRef<(msg: string, ctx?: Record<string, unknown>) => Promise<void>>(async () => {});
  const scanWsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startScanRef = useRef<(repoUrl: string, overrideAuth?: { proofToken?: string; githubToken?: string }) => void>(() => {});
  const autoFixActionRef = useRef<(directCommit?: boolean) => void>(() => {});
  const verifyInFlightRef = useRef(false);
  const lastFocusPollRef = useRef(0);

  const activatePendingVerify = useCallback((challenge: PendingVerifyChallenge) => {
    setPendingVerify({ ...challenge, checks: 0 });
    setOwnershipBlockedRepo(challenge.repoName);
    setVerifyTarget(challenge.repoName);
  }, []);

  const checkOwnershipOnce = useCallback(
    async (repoName: string, challengeCode: string, manual = false) => {
      if (verifyInFlightRef.current) return;
      verifyInFlightRef.current = true;
      if (manual) setIsCheckingVerify(true);
      try {
        const res = await fetch('/api/v1/verify/ownership', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: repoName,
            method: 'challenge',
            challenge_code: challengeCode,
          }),
        });
        if (!res.ok) return;
        const data = await res.json();
        setPendingVerify((prev) =>
          prev && prev.repoName.toLowerCase() === repoName.toLowerCase()
            ? { ...prev, checks: prev.checks + 1 }
            : prev
        );

        if (data.verified && data.proof_token) {
          const verifiedRepo = data.target || repoName;
          setPendingVerify(null);
          setOwnershipBlockedRepo(null);
          setOrcaChatReply('');
          setAuthorship((prev) => ({
            ...prev,
            verified: true,
            target: verifiedRepo,
            targetType: 'github',
            method: data.method || 'challenge',
            actor: data.username || data.repo_owner || 'verified-author',
            role: data.role || 'VerifiedAuthor',
            canCreatePr: Boolean(data.can_create_pr),
            message: data.message || `Авторство ${verifiedRepo} подтверждено.`,
            proofToken: data.proof_token,
          }));
          setMessages((prev) =>
            prev.map((m) =>
              m.verifyCard && m.verifyCard.repoName.toLowerCase() === repoName.toLowerCase()
                ? { ...m, verifyCard: { ...m.verifyCard, verified: true } }
                : m
            )
          );
          // Auto-start scan immediately using the freshly minted proof token!
          startScanRef.current(verifiedRepo, { proofToken: data.proof_token });
        } else if (manual) {
          setOrcaChatReply('Пока не вижу коммит в GitHub — убедись, что нажал зелёную кнопку «Commit changes»!');
        }
      } catch {
        // Silent retry on next automatic tick
      } finally {
        verifyInFlightRef.current = false;
        if (manual) setIsCheckingVerify(false);
      }
    },
    []
  );

  // Automatic zero-terminal GitHub verification poller (ETag-cached on server -> 0 quota on 304)
  const pendingRepoName = pendingVerify?.repoName ?? null;
  const pendingChallengeCode = pendingVerify?.challengeCode ?? null;
  useEffect(() => {
    if (!pendingRepoName || !pendingChallengeCode) return;
    let ticks = 0;
    const maxTicks = 90; // ~5.5 minutes

    const tick = () => {
      ticks += 1;
      if (ticks > maxTicks) {
        setPendingVerify(null);
        return;
      }
      void checkOwnershipOnce(pendingRepoName, pendingChallengeCode, false);
    };

    const intervalId = setInterval(tick, 3500);

    // Check immediately when user switches back from the GitHub tab after clicking Commit!
    const handleReturnToTab = () => {
      if (document.visibilityState === 'hidden') return;
      const now = Date.now();
      if (now - lastFocusPollRef.current < 1200) return;
      lastFocusPollRef.current = now;
      void checkOwnershipOnce(pendingRepoName, pendingChallengeCode, false);
    };
    window.addEventListener('focus', handleReturnToTab);
    document.addEventListener('visibilitychange', handleReturnToTab);

    return () => {
      clearInterval(intervalId);
      window.removeEventListener('focus', handleReturnToTab);
      document.removeEventListener('visibilitychange', handleReturnToTab);
    };
  }, [pendingRepoName, pendingChallengeCode, checkOwnershipOnce]);

  useEffect(() => {
    let active = true;
    const pollHealth = async () => {
      try {
        const res = await fetch('/api/ai/config', { cache: 'no-store' });
        if (!res.ok || !active) return;
        const cfg = await res.json();
        const online = cfg.is_local ? Boolean(cfg.ollama_reachable) : Boolean(cfg.has_api_key);
        setOllamaOnline(online);
        if (cfg.model) {
          setOllamaModel(cfg.is_local ? cfg.model : `${cfg.provider}:${cfg.model}`);
        }
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
        if (wsWatchdogRef.current) {
          clearTimeout(wsWatchdogRef.current);
          wsWatchdogRef.current = null;
        }
        wsPendingRef.current = null;
        const data = JSON.parse(event.data);
        if (data.type === 'authorship' && data.proof_token) {
          setPendingVerify(null);
          setOwnershipBlockedRepo(null);
          setOrcaChatReply('');
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
        } else if (data.type === 'verify_challenge' && data.challenge_code && data.verify_url) {
          setIsTyping(false);
          const card: ChatVerifyCard = {
            repoName: data.repo_name,
            challengeCode: data.challenge_code,
            verifyUrl: data.verify_url,
            verifyFilename: data.verify_filename || 'verify.txt',
          };
          activatePendingVerify(card);
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            {
              id: `${Date.now()}`,
              role: 'assistant',
              content: data.message || `Подтверди авторство \`${data.repo_name}\` в 1 клик — я сама проверю GitHub и запущу аудит!`,
              verifyCard: card,
              timestamp: formatNowTime(),
            },
          ]);
        } else if (data.type === 'action' && data.action === 'AUTOFIX') {
          setIsTyping(false);
          setMessages((prev) => prev.filter((m) => m.id !== 'streaming'));
          autoFixActionRef.current(Boolean(data.direct_commit));
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
              const spoken = summarizeSpeechLine(last.content);
              if (spoken) setOrcaChatReply(spoken);
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
        if (wsWatchdogRef.current) {
          clearTimeout(wsWatchdogRef.current);
          wsWatchdogRef.current = null;
        }
        if (wsPendingRef.current) {
          const pending = wsPendingRef.current;
          wsPendingRef.current = null;
          void httpChatFallbackRef.current(pending.message, pending.scan_context);
        }
        if (!unmounted) reconnectTimer = setTimeout(connectChatWs, 3000);
      };
    };

    connectChatWs();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsWatchdogRef.current) clearTimeout(wsWatchdogRef.current);
      if (chatWsRef.current) chatWsRef.current.onclose = null;
      chatWsRef.current?.close();
      scanWsRef.current?.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [activatePendingVerify]);

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
          if (saved.authorship && typeof saved.authorship === 'object' && saved.authorship.proofToken) {
            setAuthorship({
              ...EMPTY_AUTHORSHIP,
              verified: Boolean(saved.authorship.verified),
              target: String(saved.authorship.target || ''),
              targetType: saved.authorship.targetType === 'domain' ? 'domain' : 'github',
              method: String(saved.authorship.method || 'challenge'),
              actor: String(saved.authorship.actor || ''),
              role: String(saved.authorship.role || 'VerifiedAuthor'),
              message: String(saved.authorship.message || ''),
              proofToken: String(saved.authorship.proofToken || ''),
              githubToken: '',
            });
          }
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
          // Persist only short-lived signed proof_token (never persist raw githubToken PAT!)
          authorship: authorship.verified && authorship.proofToken
            ? {
                verified: true,
                target: authorship.target,
                targetType: authorship.targetType,
                method: authorship.method,
                actor: authorship.actor,
                role: authorship.role,
                message: authorship.message,
                proofToken: authorship.proofToken,
              }
            : null,
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
    authorship,
  ]);

  const resetScanState = (targetLabel: string) => {
    setOwnershipBlockedRepo(null);
    setPendingVerify(null);
    setOrcaChatReply('');
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
    system_analysis?: SystemAnalysisSummary | null;
    scan_result?: { duration_seconds?: number; system_analysis?: SystemAnalysisSummary | null };
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
    setSystemAnalysis(data.system_analysis ?? data.scan_result?.system_analysis ?? null);
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

  const deliverChatOverHttp = useCallback(
    async (userMsg: string, scanContext?: Record<string, unknown>) => {
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
          setPendingVerify(null);
          setOwnershipBlockedRepo(null);
          setOrcaChatReply('');
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
        if (data.verify_challenge?.challenge_code && data.verify_challenge?.verify_url) {
          const vc = data.verify_challenge;
          const card: ChatVerifyCard = {
            repoName: vc.repo_name,
            challengeCode: vc.challenge_code,
            verifyUrl: vc.verify_url,
            verifyFilename: vc.verify_filename || 'verify.txt',
          };
          activatePendingVerify(card);
          setMessages((prev) => [
            ...prev.filter((m) => m.id !== 'streaming'),
            {
              id: `${Date.now() + 1}`,
              role: 'assistant',
              content: data.reply || `Подтверди авторство \`${vc.repo_name}\` в 1 клик — я сама всё проверю!`,
              verifyCard: card,
              timestamp: formatNowTime(),
            },
          ]);
          return;
        }
        if (data.action === 'AUTOFIX') {
          setMessages((prev) => prev.filter((m) => m.id !== 'streaming'));
          autoFixActionRef.current(Boolean(data.direct_commit));
          return;
        }
        if (data.action === 'SCAN' && data.github_url) {
          setMessages((prev) => prev.filter((m) => m.id !== 'streaming'));
          startScanRef.current(data.github_url);
          return;
        }
        const replyText = data.reply || 'Запрос обработан.';
        const spoken = summarizeSpeechLine(replyText);
        if (spoken) setOrcaChatReply(spoken);
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== 'streaming'),
          {
            id: `${Date.now() + 1}`,
            role: 'assistant',
            content: replyText,
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
    },
    [activatePendingVerify]
  );

  useEffect(() => {
    httpChatFallbackRef.current = deliverChatOverHttp;
  }, [deliverChatOverHttp]);

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
              system_analysis: systemAnalysis,
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
        await deliverChatOverHttp(userMsg, scanContext);
        return;
      }

      setIsTyping(true);
      setMessages((prev) => [...prev, { id: 'streaming', role: 'assistant', content: '', timestamp: now }]);

      wsPendingRef.current = { message: userMsg, scan_context: scanContext };
      if (wsWatchdogRef.current) clearTimeout(wsWatchdogRef.current);
      wsWatchdogRef.current = setTimeout(() => {
        if (wsPendingRef.current) {
          const pending = wsPendingRef.current;
          wsPendingRef.current = null;
          wsWatchdogRef.current = null;
          void deliverChatOverHttp(pending.message, pending.scan_context);
        }
      }, 22000);

      chatWsRef.current.send(
        JSON.stringify({
          message: userMsg,
          scan_context: scanContext,
        })
      );
    },
    [activeTarget, findings, grade, securityScore, activeFindingsCount, financialRisk, systemAnalysis, appealedMap, deliverChatOverHttp]
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
    setPendingVerify(null);
    setOrcaChatReply('');
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

  const runRepoScanHttpFallback = async (
    clean: string,
    overrideAuth?: { proofToken?: string; githubToken?: string }
  ) => {
    const effectiveGithubToken = overrideAuth?.githubToken ?? authorship.githubToken;
    const effectiveProofToken = overrideAuth?.proofToken ?? authorship.proofToken;
    try {
      const res = await fetch('/api/scan/repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          github_url: clean,
          github_token: effectiveGithubToken || undefined,
          proof_token: effectiveProofToken || undefined,
          require_ownership: requireOwnership,
        }),
      });
      const data = await res.json();
      const verifyCard: ChatVerifyCard | undefined =
        !res.ok && data.code === 'OWNERSHIP_REQUIRED' && data.challenge_code && data.verify_url
          ? {
              repoName: data.repo_name || clean,
              challengeCode: data.challenge_code,
              verifyUrl: data.verify_url,
              verifyFilename: data.verify_filename || 'verify.txt',
            }
          : undefined;

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
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: verifyCard
              ? data.error || `Подтверди авторство \`${verifyCard.repoName}\` в 1 клик:`
              : `⛔ ${data.error || 'Не удалось выполнить скан репозитория.'}`,
            verifyCard,
            timestamp: formatNowTime(),
          },
        ];
      });
      if (res.ok) {
        applyCompletedPayload(data);
      } else {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        if (data.code === 'OWNERSHIP_REQUIRED') {
          if (verifyCard) {
            activatePendingVerify(verifyCard);
          } else {
            setOwnershipBlockedRepo(data.repo_name || clean);
            if (data.repo_name) setVerifyTarget(data.repo_name);
          }
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

  const startScan = (repoUrl: string, overrideAuth?: { proofToken?: string; githubToken?: string }) => {
    const clean = repoUrl.trim();
    if (!clean) return;
    const effectiveGithubToken = overrideAuth?.githubToken ?? authorship.githubToken;
    const effectiveProofToken = overrideAuth?.proofToken ?? authorship.proofToken;
    setRepoScanUrl(clean);
    setVerifyTarget(clean);
    resetScanState(clean);

    const now = formatNowTime();
    setMessages((prev) => [
      ...prev.filter((m) => m.id !== 'scan-status' && m.id !== 'streaming'),
      { id: 'scan-status', role: 'assistant', content: `Проверяю авторство и запускаю аудит \`${clean}\`...`, timestamp: now },
    ]);

    // If WebSocket transport isn't active in this tunnel/proxy (e.g. ngrok HTTP/2), skip WS immediately -> instant HTTPS!
    if (!chatWsRef.current || chatWsRef.current.readyState !== WebSocket.OPEN) {
      void runRepoScanHttpFallback(clean, overrideAuth);
      return;
    }

    let finished = false;
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/scan`;
    const ws = new WebSocket(wsUrl);
    scanWsRef.current = ws;

    const fallbackToHttp = () => {
      if (finished) return;
      finished = true;
      clearTimeout(connectTimer);
      try {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
      } catch {
        // ignore
      }
      void runRepoScanHttpFallback(clean, overrideAuth);
    };

    // Hard 1.8s connect timeout so a stalled WS Upgrade can NEVER freeze verification/scanning
    const connectTimer = setTimeout(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        fallbackToHttp();
      }
    }, 1800);

    ws.onopen = () => {
      clearTimeout(connectTimer);
      ws.send(
        JSON.stringify({
          github_url: clean,
          github_token: effectiveGithubToken || undefined,
          proof_token: effectiveProofToken || undefined,
          require_ownership: requireOwnership,
        })
      );
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.event_type === 'ScanResult') {
        finished = true;
        clearTimeout(connectTimer);
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
        clearTimeout(connectTimer);
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
        const verifyCard: ChatVerifyCard | undefined =
          data.code === 'OWNERSHIP_REQUIRED' && data.challenge_code && data.verify_url
            ? {
                repoName: data.repo_name || clean,
                challengeCode: data.challenge_code,
                verifyUrl: data.verify_url,
                verifyFilename: data.verify_filename || 'verify.txt',
              }
            : undefined;
        if (data.code === 'OWNERSHIP_REQUIRED') {
          if (verifyCard) {
            activatePendingVerify(verifyCard);
          } else {
            setOwnershipBlockedRepo(data.repo_name || clean);
            if (data.repo_name) setVerifyTarget(data.repo_name);
          }
        }
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== 'scan-status'),
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: verifyCard ? data.message : `⛔ ${data.message}`,
            verifyCard,
            timestamp: formatNowTime(),
          },
        ]);
      } else if (data.event_type === 'ScanCompleted') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };

    ws.onerror = () => fallbackToHttp();
    ws.onclose = () => fallbackToHttp();
  };

  useEffect(() => {
    startScanRef.current = startScan;
  });

  const handleAutoFixRepo = async (
    repoName: string,
    opts?: { githubToken?: string; directCommit?: boolean; messageId?: string }
  ) => {
    if (isHealing) return;
    const clean = repoName.trim();
    if (!clean) return;
    const effectiveToken = (opts?.githubToken || authorship.githubToken || '').trim();
    if (opts?.githubToken) {
      setAuthorship((prev) => ({ ...prev, githubToken: opts.githubToken!.trim() }));
    }

    setIsHealing(true);
    setOrcaChatReply('');
    const now = formatNowTime();
    if (!opts?.messageId) {
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'scan-status'),
        {
          id: 'scan-status',
          role: 'assistant',
          content: effectiveToken
            ? `Исправляю уязвимости в \`${clean}\` → пересканирую SAST → коммичу патчи в GitHub…`
            : `Исправляю уязвимости в \`${clean}\` и проверяю патчи пересканированием…`,
          timestamp: now,
        },
      ]);
    }

    try {
      const res = await fetch('/api/repo/autofix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          github_url: clean,
          proof_token: authorship.proofToken || undefined,
          github_token: effectiveToken || undefined,
          commit_to_github: true,
          direct_commit: Boolean(opts?.directCommit),
          require_ownership: requireOwnership,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        const verifyCard: ChatVerifyCard | undefined =
          data.code === 'OWNERSHIP_REQUIRED' && data.challenge_code && data.verify_url
            ? {
                repoName: data.repo_name || clean,
                challengeCode: data.challenge_code,
                verifyUrl: data.verify_url,
                verifyFilename: data.verify_filename || 'verify.txt',
              }
            : undefined;
        if (verifyCard) activatePendingVerify(verifyCard);
        setMessages((prev) => [
          ...prev.filter((m) => m.id !== 'scan-status'),
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: verifyCard ? data.error : `⛔ ${data.error || 'Не удалось выполнить авто-исправление.'}`,
            verifyCard,
            timestamp: formatNowTime(),
          },
        ]);
        return;
      }

      const commitCard: ChatCommitCard = {
        repoName: data.repo_name || clean,
        beforeScore: data.before_score ?? 0,
        beforeGrade: data.before_grade ?? '—',
        afterScore: data.after_score ?? 0,
        afterGrade: data.after_grade ?? '—',
        beforeFindings: data.before_findings ?? 0,
        afterFindings: data.after_findings ?? 0,
        fixedCount: data.fixed_count ?? 0,
        fixes: Array.isArray(data.fixes) ? data.fixes : [],
        committed: Boolean(data.committed),
        needsToken: Boolean(data.needs_token),
        directCommit: Boolean(data.direct_commit),
        branchName: data.branch_name ?? null,
        commitSha: data.commit_sha ?? null,
        commitUrl: data.commit_url ?? null,
        pullRequestUrl: data.pull_request_url ?? null,
        filesCommitted: Array.isArray(data.files_committed) ? data.files_committed : [],
        tokenCreateUrl: data.token_create_url,
        commitMessage: data.commit_message || '',
      };

      const headline = commitCard.committed
        ? `Готово! Исправила **${commitCard.fixedCount}** проблем (Score **${commitCard.beforeScore} → ${commitCard.afterScore}**) и сама запушила коммит в GitHub:`
        : commitCard.fixes.length > 0
        ? `Проверенные патчи готовы: Score **${commitCard.beforeScore} (${commitCard.beforeGrade}) → ${commitCard.afterScore} (${commitCard.afterGrade})**, находок **${commitCard.beforeFindings} → ${commitCard.afterFindings}**. Вставь GitHub Token ниже — сразу сделаю коммит!`
        : `Проверила \`${commitCard.repoName}\`: безопасных авто-фиксов не нашлось (${commitCard.commitMessage || 'требуется ручной разбор'}).`;

      setOrcaChatReply(
        commitCard.committed
          ? `Готово! Исправила ${commitCard.fixedCount} проблем и сама закоммитила в GitHub!`
          : commitCard.fixes.length > 0
          ? `Патчи готовы и проверены: Score вырос с ${commitCard.beforeScore} до ${commitCard.afterScore}! Вставь токен — закоммичу в GitHub.`
          : 'Безопасных авто-фиксов для этих находок нет — нужен ручной разбор.'
      );

      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== 'scan-status');
        if (opts?.messageId) {
          return filtered.map((m) =>
            m.id === opts.messageId
              ? { ...m, content: headline, commitCard, timestamp: formatNowTime() }
              : m
          );
        }
        return [
          ...filtered,
          {
            id: `${Date.now()}`,
            role: 'assistant',
            content: headline,
            commitCard,
            timestamp: formatNowTime(),
          },
        ];
      });

      if (commitCard.fixes.length > 0) {
        setHealReport(data);
        setSecurityScore(data.after_score);
        setGrade(data.after_grade);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev.filter((m) => m.id !== 'scan-status'),
        {
          id: `${Date.now()}`,
          role: 'assistant',
          content: `⛔ Ошибка сети при авто-исправлении: ${err}`,
          timestamp: formatNowTime(),
        },
      ]);
    } finally {
      setIsHealing(false);
    }
  };

  useEffect(() => {
    autoFixActionRef.current = (directCommit = false) => {
      if (activeTarget === 'demo/kz-fintech-app') {
        void handleDemoHeal();
        return;
      }
      if (activeTarget && !activeTarget.startsWith('upload/') && activeTarget.includes('/')) {
        void handleAutoFixRepo(activeTarget, { directCommit });
        return;
      }
      setMessages((prev) => [
        ...prev,
        {
          id: `${Date.now()}`,
          role: 'assistant',
          content:
            'Сначала вставь ссылку на свой GitHub-репозиторий (например `https://github.com/owner/repo`) или нажми **«Демо-аудит»**, чтобы я нашла баги, исправила их и сделала коммит!',
          timestamp: formatNowTime(),
        },
      ]);
    };
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
    if (isHealing) return 'Патчу уязвимый код, прогоняю ast.parse и пересканирую песочницу…';
    if (isScanning) return `Просвечиваю ${activeTarget || 'репозиторий'} сонаром: AST, Taint, секреты и Git-история…`;
    if (isTyping) return 'Думаю над твоим вопросом — анализирую через AI-движок…';
    if (pendingVerify) {
      return `Жду подтверждение ${pendingVerify.repoName}! Нажми кнопку в чате и кликни Commit на GitHub — я сама проверю и сразу запущу скан!`;
    }
    if (ownershipBlockedRepo) {
      return `Стоп! Репозиторий ${ownershipBlockedRepo} без подтверждения авторства не пропущу. Подтверди в 1 клик в чате!`;
    }
    if (orcaChatReply) {
      return orcaChatReply;
    }
    if (healReport) {
      return `Готово! Исцелила ${healReport.fixed_count} уязвимостей: Score вырос с ${healReport.before_score} до ${healReport.after_score} (${healReport.after_grade})!`;
    }
    if (securityScore !== null && activeFindingsCount > 0) {
      return securityScore < 70
        ? `Тревога! Нашла ${activeFindingsCount} проблем в ${activeTarget}, Score ${securityScore} из 100. Жми Self-Heal или открой «Находки»!`
        : `Проверила ${activeTarget}: Score ${securityScore} из 100 (${grade}). Есть ${activeFindingsCount} мелких замечаний — по критике чисто.`;
    }
    if (securityScore !== null && activeFindingsCount === 0) {
      return `Вода чиста в ${activeTarget}! Score ${securityScore} из 100 (${grade}) — ни одной активной угрозы.`;
    }
    if (authorship.verified) {
      return `Авторство ${authorship.target} подтверждено! Запускаю аудит или жду твой вопрос.`;
    }
    return 'Привет! Я Aegis Orca. Кидай ссылку на свой GitHub — я сама проверю авторство в 1 клик и найду все дыры, или жми «Демо-аудит»!';
  }, [
    isHealing,
    isScanning,
    isTyping,
    activeTarget,
    pendingVerify,
    ownershipBlockedRepo,
    orcaChatReply,
    healReport,
    securityScore,
    activeFindingsCount,
    grade,
    authorship.verified,
    authorship.target,
  ]);

  const isRealActiveRepo =
    Boolean(activeTarget) &&
    activeTarget !== 'demo/kz-fintech-app' &&
    !activeTarget.startsWith('upload/') &&
    activeTarget.includes('/');
  const canSelfHealDemo =
    (activeTarget === 'demo/kz-fintech-app' || isRealActiveRepo) && findings.length > 0 && !healReport;

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

      {/* 5px Stepped 16-Bit Candy-Cane & Holly Christmas Ribbon */}
      <div className="pixel-aurora-bar" aria-hidden="true" />

      {/* Single Compact 54px Christmas Pixel App Top Bar */}
      <header className="h-[54px] shrink-0 border-b-2 border-[var(--color-line)] bg-[var(--color-paper)] px-4 sm:px-5 flex items-center justify-between gap-3 z-30">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2.5 shrink-0">
            <ChristmasTreeBadge />
            <span className="font-pixel text-[11px] sm:text-[12px] tracking-tight leading-none">
              commit<span className="text-[#e93e32]">.</span>guardian
            </span>
            <span className="hidden xl:inline-block font-pixel text-[8px] px-1.5 py-0.5 bg-[#e93e32] text-[#ffd866] border border-[#ffd866] shadow-[2px_2px_0_var(--pixel-shadow)]">
              XMAS
            </span>
          </div>
          <AiModelSwitcher
            onStatusChange={(cfg) => {
              setOllamaOnline(cfg.is_local ? cfg.ollama_reachable : true);
              setOllamaModel(cfg.is_local ? cfg.model : `${cfg.provider}:${cfg.model}`);
            }}
          />
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <a
            href="/dashboard"
            className="pixel-btn hidden sm:inline-flex items-center gap-1 min-h-8 px-2.5 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11.5px]"
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
              'pixel-btn min-h-8 px-2.5 font-mono text-[11.5px] inline-flex items-center gap-1.5 cursor-pointer',
              drawerOpen
                ? '!border-[#e93e32] bg-[#e93e32]/20 text-[var(--color-ink)]'
                : 'bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
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
            className="pixel-btn-primary min-h-8 px-3.5 disabled:opacity-55 text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Zap className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Демо-аудит</span>
          </button>
        </div>
      </header>

      {/* Hanging 16-Bit Pixel Pine Garland & Twinkling Christmas Fairy Lights */}
      <ChristmasLightsGarland paused={motionPaused || Boolean(prefersReducedMotion)} />

      {/* Pure Full-Viewport Companion + Chat Shell */}
      <main id="chat-workspace" className="flex-1 min-h-0 flex flex-col lg:flex-row relative overflow-hidden">
        {/* Left: Live Animated 16-Bit Christmas Pixel-Art Orca Companion */}
        <div className="lg:w-[320px] xl:w-[348px] lg:h-full shrink-0 flex flex-col pt-3 lg:pt-3.5 bg-[var(--color-paper)]">
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
            motionPaused={motionPaused}
            onToggleMotionPaused={() => setMotionPaused((p) => !p)}
            onDemoScan={handleDemoScan}
            onTriggerSelfHeal={() => {
              if (isRealActiveRepo) {
                void handleAutoFixRepo(activeTarget);
              } else {
                void handleDemoHeal();
              }
            }}
            onUploadZipClick={() => document.getElementById(zipInputId)?.click()}
            onOpenDrawer={openDrawerTab}
          />
        </div>

        {/* Center: Full-Height Pure Chat Stream */}
        <div className="flex-1 min-w-0 min-h-0 flex flex-col pt-3 lg:pt-3.5 bg-[var(--color-paper)]">
          <AiCopilotChat
            messages={messages}
            input={input}
            onInputChange={setInput}
            onSubmit={handleSendMessage}
            onQuickPrompt={(prompt) => sendChatText(prompt)}
            onResetChat={handleResetChat}
            onUploadZip={handleZipUpload}
            onTriggerSelfHeal={handleDemoHeal}
            onAutoFixRepo={(repo, opts) => {
              void handleAutoFixRepo(repo, opts);
            }}
            onOpenFindingsDrawer={() => openDrawerTab('findings')}
            onOpenAuthorshipDrawer={() => openDrawerTab('authorship')}
            onCheckVerifyNow={(repo, code) => {
              void checkOwnershipOnce(repo, code, true);
            }}
            pendingVerifyRepo={pendingVerify?.repoName ?? null}
            pendingVerifyChecks={pendingVerify?.checks ?? 0}
            isCheckingVerify={isCheckingVerify}
            companionMood={companionMood}
            motionPaused={motionPaused || Boolean(prefersReducedMotion)}
            isHealing={isHealing}
            isTyping={isTyping}
            isScanning={isScanning}
            ollamaOnline={ollamaOnline}
            ollamaModel={ollamaModel}
            activeTarget={activeTarget}
          />
        </div>

        {/* Right: On-Demand Collapsible Pixel Inspector Drawer */}
        <AnimatePresence>
          {drawerOpen && (
            <motion.aside
              aria-label="Инспектор аудита, коммитов и авторства"
              initial={prefersReducedMotion ? { opacity: 1 } : { opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={prefersReducedMotion ? { opacity: 0 } : { opacity: 0, x: 20 }}
              transition={{ duration: 0.16, ease: 'easeOut' }}
              className="fixed inset-y-[58px] right-0 z-30 w-full max-w-[440px] lg:static lg:inset-auto lg:w-[410px] xl:w-[440px] lg:h-full lg:pt-3.5 border-l-2 border-[var(--color-line)] bg-[var(--color-paper)] flex flex-col min-h-0 shadow-[-4px_0_0_var(--pixel-shadow)] lg:shadow-none shrink-0"
            >
              {/* Drawer Tabs + Close */}
              <div className="px-3 py-2.5 border-b-2 border-[var(--color-line)] flex items-center justify-between gap-2 shrink-0">
                <div className="grid grid-cols-4 gap-1.5 flex-1 min-w-0" role="tablist" aria-label="Разделы инспектора">
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
                          'pixel-btn min-h-8 px-2 py-1 font-mono text-[11px] flex items-center justify-center gap-1 cursor-pointer truncate',
                          active
                            ? '!border-[#e94a32] bg-[#e94a32]/20 text-[var(--color-ink)] font-semibold'
                            : 'bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                        )}
                      >
                        <span className="truncate">{tab.label}</span>
                        <span className="tabular-nums opacity-75">{tab.badge}</span>
                      </button>
                    );
                  })}
                </div>

                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  aria-label="Скрыть панель инспектора"
                  className="pixel-btn min-h-8 min-w-8 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] flex items-center justify-center shrink-0 cursor-pointer"
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
                      if (next.verified) {
                        setPendingVerify(null);
                        setOwnershipBlockedRepo(null);
                      }
                    }}
                    pendingVerify={pendingVerify}
                    onChallengeIssued={(ch) => activatePendingVerify(ch)}
                    onVerifiedAutoScan={(target, proofToken, ghToken) => {
                      setDrawerOpen(false);
                      startScan(target, { proofToken, githubToken: ghToken });
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
                      className="space-y-2.5"
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
                        className="pixel-input w-full min-h-9 px-3 py-1.5 bg-[var(--color-panel)] focus:border-[#56d4b2] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
                      />
                      <div className="flex gap-2">
                        <button
                          type="submit"
                          disabled={isScanning || !repoScanUrl.trim()}
                          className="pixel-btn-snow flex-1 min-h-9 px-3 py-1.5 disabled:opacity-45 font-mono text-xs inline-flex items-center justify-center gap-1.5 cursor-pointer"
                        >
                          <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>{isScanning ? 'Сканирую…' : 'Сканировать URL'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleDemoScan}
                          disabled={isScanning}
                          className="pixel-btn min-h-9 px-3 py-1.5 bg-[var(--color-panel)] font-mono text-xs text-[var(--color-ink)] cursor-pointer"
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
                        className="pixel-btn-emerald w-full min-h-10 px-4 py-2 disabled:opacity-60 font-mono text-xs font-semibold inline-flex items-center justify-center gap-2 cursor-pointer"
                      >
                        <HeartPulse className="w-4 h-4" aria-hidden="true" />
                        <span>{isHealing ? 'Исцеляю и пересканирую…' : 'Исцелить автоматически (Self-Heal)'}</span>
                      </button>
                    )}

                    {healReport && <HealPanel report={healReport} />}
                    {financialRisk && <RiskCard risk={financialRisk} />}
                    {ghostSecrets.length > 0 && <GhostSecretsCard ghosts={ghostSecrets} />}

                    {auditSummary && (
                      <div className="pixel-panel bg-[var(--color-panel)] p-3 text-xs leading-relaxed text-[var(--color-body-text)]">
                        <span className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)] mr-1.5">
                          Заключение:
                        </span>
                        {auditSummary}
                      </div>
                    )}

                    {appealedCount > 0 && (
                      <div className="border-2 border-[#47d18c] bg-[#47d18c]/15 px-3 py-1.5 font-mono text-[11.5px] text-[#5ee8a7] flex items-center justify-between gap-2">
                        <span>Оспорено FP: {appealedCount}</span>
                        <span>Score пересчитан</span>
                      </div>
                    )}

                    {findings.length > 0 ? (
                      <div className="space-y-2.5">
                        {findings.map((f, idx) => {
                          const fKey = makeFindingKey(f);
                          const isAppealed = Boolean(appealedMap[fKey]);
                          return (
                            <div
                              key={`${f.id}-${idx}`}
                              className={cn(
                                'pixel-panel bg-[var(--color-panel)] p-3 space-y-2',
                                isAppealed && 'opacity-55'
                              )}
                            >
                              <div className="flex items-start justify-between gap-2">
                                <span className={cn('font-mono text-[10.5px] px-2 py-0.5 shrink-0', SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.INFO)}>
                                  {f.severity}
                                </span>
                                <span className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                                  {formatCweShort(f.cwe)}
                                </span>
                              </div>
                              <div className={cn('text-xs font-semibold text-[var(--color-ink)] leading-snug', isAppealed && 'line-through')}>
                                {f.title}
                              </div>
                              <div className="text-[11px] text-[var(--color-muted-soft)] truncate">
                                <code>{f.file_path}:{f.line_start || 1}</code>
                              </div>
                              <div className="flex items-center gap-2 pt-0.5">
                                <button
                                  type="button"
                                  onClick={() => handleOpenRemediation(f)}
                                  className="pixel-btn min-h-7 px-2.5 py-1 bg-[var(--color-paper)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer"
                                >
                                  <Wrench className="w-3 h-3" aria-hidden="true" />
                                  <span>Патч</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleToggleAppeal(f)}
                                  className={cn(
                                    'pixel-btn min-h-7 px-2.5 py-1 font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer',
                                    isAppealed
                                      ? '!border-[#47d18c] bg-[#47d18c]/20 text-[#5ee8a7]'
                                      : 'bg-[var(--color-paper)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
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
                      <div className="border-2 border-dashed border-[var(--color-line-strong)] p-5 text-center space-y-2.5">
                        <p className="font-mono text-xs text-[var(--color-muted-soft)]">
                          Находок пока нет — запусти «Демо-аудит» или проверь свой репозиторий.
                        </p>
                        <button
                          type="button"
                          onClick={handleDemoScan}
                          disabled={isScanning}
                          className="pixel-btn-primary min-h-8 px-4 py-1.5 font-mono text-xs cursor-pointer"
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
              <div className="px-4 py-2 border-t-2 border-[var(--color-line)] font-mono text-[11px] text-[var(--color-faint)] flex items-center justify-between gap-2 shrink-0">
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
        className="pixel-card m-auto w-[min(92vw,740px)] bg-[var(--color-paper)] text-[var(--color-ink)] p-6"
      >
        <div className="flex items-start justify-between gap-4 mb-4 pb-3 border-b-2 border-[var(--color-line)]">
          <div>
            <h2 id="remediation-dialog-title" className="font-sans text-xl font-semibold">
              {selectedFinding?.title || 'Патч безопасности'}
            </h2>
            {selectedFinding && (
              <p className="text-xs font-mono text-[var(--color-muted-soft)] mt-1">
                <code>{selectedFinding.file_path}:{selectedFinding.line_start || 1}</code> · {formatCweShort(selectedFinding.cwe)}
              </p>
            )}
          </div>
          <form method="dialog">
            <button
              type="submit"
              aria-label="Закрыть окно патча"
              className="pixel-btn min-h-9 min-w-9 p-1.5 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer inline-flex items-center justify-center"
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
              <p className="text-[#ff7b66] text-xs mt-1">{remediation.impact_analysis}</p>
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
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 bg-[#47d18c]/20 text-[#5ee8a7] border-2 border-[#47d18c]">
                    <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                    <span>AST ✓ Синтаксис проверен</span>
                  </span>
                )}
              </div>
              {remediation.validation_note && (
                <p className="text-[11.5px] font-mono text-[var(--color-muted-soft)] mb-1.5">
                  {remediation.validation_note}
                </p>
              )}
              <pre className="p-3 bg-[#080c16] border-2 border-[#30436b] text-xs overflow-x-auto text-[#5ee8a7]">
                {remediation.fixed_code}
              </pre>
            </div>

            {authorship.canCreatePr && authorship.githubToken && activeTarget.includes('/') && !activeTarget.startsWith('demo/') && !activeTarget.startsWith('upload/') && (
              <div className="pt-2 border-t-2 border-[var(--color-line)] flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  disabled={creatingPr}
                  onClick={handleCreatePR}
                  className="pixel-btn-emerald min-h-9 px-4 py-1.5 font-mono text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>{creatingPr ? 'Создаю PR...' : 'Создать Pull Request'}</span>
                </button>
                {prStatus && <span className="font-mono text-xs text-[#47d18c] break-all">{prStatus}</span>}
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

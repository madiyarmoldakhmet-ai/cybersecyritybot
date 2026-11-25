'use client';

import { FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import {
  ArrowUp,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileDown,
  FileText,
  GitBranch,
  GitCommitHorizontal,
  GitPullRequest,
  HeartPulse,
  KeyRound,
  Loader2,
  Paperclip,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  Wrench,
} from 'lucide-react';
import { OrcaMiniAvatar, OrcaMood } from '@/components/OrcaRigSvg';
import { PixelSnowfallLayer, PixelWinterHorizon } from '@/components/ChristmasDecor';
import { cn } from '@/lib/utils';

export type ChatVerifyCard = {
  repoName: string;
  challengeCode: string;
  verifyUrl: string;
  verifyFilename?: string;
  verified?: boolean;
};

export type ChatCommitFixItem = {
  file_path: string;
  fixers: string[];
  diff: string;
  fixed_findings: string[];
  verified: boolean;
};

export type ChatCommitCard = {
  repoName: string;
  beforeScore: number;
  beforeGrade: string;
  afterScore: number;
  afterGrade: string;
  beforeFindings: number;
  afterFindings: number;
  fixedCount: number;
  fixes: ChatCommitFixItem[];
  committed: boolean;
  needsToken?: boolean;
  directCommit?: boolean;
  branchName?: string | null;
  commitSha?: string | null;
  commitUrl?: string | null;
  pullRequestUrl?: string | null;
  filesCommitted?: string[];
  tokenCreateUrl?: string;
  commitMessage?: string;
};

export type SystemAnalysisSummary = {
  tech_stack?: string[];
  datastores?: string[];
  infrastructure?: string[];
  files_analyzed?: number;
  endpoints_total?: number;
  non_public_endpoints?: number;
  protected_endpoints?: number;
  auth_coverage_pct?: number | null;
  unprotected_mutations?: { method: string; path: string; location: string }[];
  trust_boundaries?: string[];
  stride_breakdown?: Record<string, number>;
  risk_chains?: { severity: string; title: string; steps: string[]; defense?: string }[];
  remediation_roadmap?: string[];
};

export type ChatAuditCard = {
  repoName: string;
  commitSha?: string;
  branch?: string;
  author?: string;
  durationSeconds?: number;
  score: number | null;
  grade: string | null;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  riskKzt?: number;
  summary?: string;
  pdfUrl?: string | null;
  mdUrl?: string | null;
  topFindings?: { severity: string; title: string; location: string }[];
  systemAnalysis?: SystemAnalysisSummary | null;
  canSelfHeal?: boolean;
  isRealRepo?: boolean;
};

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  auditCard?: ChatAuditCard;
  verifyCard?: ChatVerifyCard;
  commitCard?: ChatCommitCard;
};

interface AiCopilotChatProps {
  messages: ChatMessage[];
  input: string;
  onInputChange: (value: string) => void;
  onSubmit: (e: FormEvent) => void;
  onQuickPrompt: (prompt: string) => void;
  onResetChat: () => void;
  onUploadZip: (file: File) => void;
  onTriggerSelfHeal?: () => void;
  onAutoFixRepo?: (repoName: string, opts?: { githubToken?: string; directCommit?: boolean; messageId?: string }) => void;
  onOpenFindingsDrawer?: () => void;
  onOpenAuthorshipDrawer?: () => void;
  onCheckVerifyNow?: (repoName: string, challengeCode: string) => void;
  pendingVerifyRepo?: string | null;
  pendingVerifyChecks?: number;
  isCheckingVerify?: boolean;
  companionMood?: OrcaMood;
  motionPaused?: boolean;
  isHealing?: boolean;
  isTyping: boolean;
  isScanning: boolean;
  ollamaOnline: boolean | null;
  ollamaModel: string;
  activeTarget: string;
  className?: string;
}

const QUICK_PROMPTS = [
  'Системный анализ и цепочки угроз',
  'Исправь и закоммить в GitHub',
  'Объясни критичные баги',
  'Оцени риск в тенге (КоАП РК)',
];

function renderCodeSpans(text: string, keyPrefix: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return (
        <code
          key={`${keyPrefix}-c-${idx}`}
          className="text-[0.86em] px-1.5 py-0.5 bg-[var(--color-canvas)] border border-[var(--color-line-strong)] text-[#56d4b2] break-words"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={`${keyPrefix}-t-${idx}`}>{part}</span>;
  });
}

function renderInlineFormatting(line: string, keyPrefix: string): ReactNode[] {
  const headingMatch = line.match(/^#{1,3}\s+(.+)$/);
  if (headingMatch) {
    return [
      <strong key={`${keyPrefix}-h`} className="font-semibold text-[var(--color-ink)] block">
        {renderInlineFormatting(headingMatch[1], `${keyPrefix}-hi`)}
      </strong>,
    ];
  }

  const tokens = line.split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g);
  return tokens.map((token, idx) => {
    if (token.startsWith('**') && token.endsWith('**') && token.length >= 4) {
      return (
        <strong key={`${keyPrefix}-${idx}`} className="font-semibold text-[var(--color-ink)]">
          {renderCodeSpans(token.slice(2, -2), `${keyPrefix}-b-${idx}`)}
        </strong>
      );
    }
    if (token.startsWith('`') && token.endsWith('`') && token.length >= 2) {
      return (
        <code
          key={`${keyPrefix}-${idx}`}
          className="text-[0.86em] px-1.5 py-0.5 bg-[var(--color-canvas)] border border-[var(--color-line-strong)] text-[#56d4b2] break-words"
        >
          {token.slice(1, -1)}
        </code>
      );
    }
    if (token.startsWith('*') && token.endsWith('*') && token.length >= 3 && !token.startsWith('**')) {
      return (
        <em key={`${keyPrefix}-${idx}`} className="italic text-[var(--color-ink)]">
          {renderCodeSpans(token.slice(1, -1), `${keyPrefix}-em-${idx}`)}
        </em>
      );
    }
    return <span key={`${keyPrefix}-${idx}`}>{token}</span>;
  });
}

function FormattedBubbleContent({ content }: { content: string }) {
  const segments = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-2 text-[14.5px] leading-[1.55] break-words [overflow-wrap:anywhere]">
      {segments.map((segment, segIdx) => {
        if (segment.startsWith('```') && segment.endsWith('```') && segment.length >= 6) {
          const inner = segment.slice(3, -3).replace(/^[a-zA-Z0-9_-]+\n/, '');
          return (
            <pre
              key={`code-${segIdx}`}
              className="text-xs p-3 overflow-x-auto bg-[#080c16] border-2 border-[#30436b] text-[#5ee8a7]"
            >
              <code>{inner.trim()}</code>
            </pre>
          );
        }

        const lines = segment.split('\n');
        return lines.map((line, lineIdx) => (
          <p key={`txt-${segIdx}-${lineIdx}`} className={line.trim() ? '' : 'h-1'}>
            {renderInlineFormatting(line, `${segIdx}-${lineIdx}`)}
          </p>
        ));
      })}
    </div>
  );
}

function formatKztInline(n: number): string {
  return `${Math.round(n).toLocaleString('ru-RU').replace(/,/g, ' ')} ₸`;
}

function TelegramAuditCard({
  card,
  onTriggerSelfHeal,
  onAutoFixRepo,
  onOpenFindingsDrawer,
  isHealing,
}: {
  card: ChatAuditCard;
  onTriggerSelfHeal?: () => void;
  onAutoFixRepo?: (repoName: string, opts?: { githubToken?: string; directCommit?: boolean; messageId?: string }) => void;
  onOpenFindingsDrawer?: () => void;
  isHealing?: boolean;
}) {
  const isClean = card.critical === 0 && card.high === 0;
  return (
    <div className="pixel-card mt-1.5 bg-[var(--color-panel)] p-3.5 space-y-2.5 text-xs">
      {/* Header matching Telegram Bot _format_scan_summary */}
      <div className="flex items-start justify-between gap-2 pb-2 border-b-2 border-[var(--color-line)]">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 font-semibold text-[var(--color-ink)]">
            {isClean ? (
              <ShieldCheck className="w-4 h-4 text-[#47d18c] shrink-0" aria-hidden="true" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-[#e94a32] shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">{card.repoName}</span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11px] text-[var(--color-muted-soft)]">
            {card.branch && (
              <span className="inline-flex items-center gap-0.5">
                <GitBranch className="w-3 h-3" aria-hidden="true" />
                {card.branch}
              </span>
            )}
            {card.commitSha && <code>{card.commitSha.slice(0, 8)}</code>}
            {card.author && <span>@{card.author}</span>}
            {typeof card.durationSeconds === 'number' && card.durationSeconds > 0 && (
              <span>{card.durationSeconds.toFixed(1)} с</span>
            )}
          </div>
        </div>
        <div
          className={cn(
            'font-mono text-xs font-semibold px-2 py-0.5 border-2 tabular-nums shrink-0',
            isClean
              ? 'bg-[#47d18c]/20 text-[#5ee8a7] border-[#47d18c]'
              : 'bg-[#e94a32]/20 text-[#ff8573] border-[#e94a32]'
          )}
        >
          {card.score ?? '—'}/100 ({card.grade ?? '—'})
        </div>
      </div>

      {/* Severity Counts */}
      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] tabular-nums">
        <span className="text-[var(--color-muted-soft)]">Находок: <b className="text-[var(--color-ink)]">{card.totalFindings}</b></span>
        <span className="px-1.5 py-0.5 border border-[#e94a32] bg-[#e94a32]/20 text-[#ff8573]">CRIT {card.critical}</span>
        <span className="px-1.5 py-0.5 border border-orange-500/60 bg-orange-500/20 text-orange-300">HIGH {card.high}</span>
        <span className="px-1.5 py-0.5 border border-[#f0b541]/60 bg-[#f0b541]/20 text-[#ffe79e]">MED {card.medium}</span>
        <span className="px-1.5 py-0.5 border border-[#2da890] bg-[#2da890]/20 text-[#56d4b2]">LOW {card.low}</span>
      </div>

      {/* Financial Risk */}
      {card.riskKzt && card.riskKzt > 0 ? (
        <div className="px-2.5 py-1.5 bg-[#e94a32]/15 border-2 border-[#e94a32] font-mono text-[11.5px] text-[#ff8573]">
          Риск (ст. 79 КоАП РК): <b>до {formatKztInline(card.riskKzt)}</b>
        </div>
      ) : null}

      {/* Top Findings list */}
      {card.topFindings && card.topFindings.length > 0 && (
        <div className="space-y-1">
          <div className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
            Топ находок
          </div>
          <ol className="space-y-1">
            {card.topFindings.slice(0, 5).map((f, i) => (
              <li key={i} className="text-[12px] leading-snug text-[var(--color-body-text)]">
                <span className="font-mono text-[10.5px] text-[#ff7b66] mr-1">[{f.severity}]</span>
                <span className="text-[var(--color-ink)]">{f.title}</span>{' '}
                <code className="text-[10.5px] text-[var(--color-muted-soft)]">{f.location}</code>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Systems Analyst Architecture, STRIDE & Risk Chains (native <details> disclosure) */}
      {card.systemAnalysis &&
        ((card.systemAnalysis.tech_stack?.length ?? 0) > 0 ||
          (card.systemAnalysis.endpoints_total ?? 0) > 0 ||
          (card.systemAnalysis.risk_chains?.length ?? 0) > 0) && (
          <details className="border-2 border-[var(--color-line)] bg-[var(--color-paper)] px-2.5 py-2 text-[12px]">
            <summary className="cursor-pointer font-mono text-[11.5px] font-semibold text-[var(--color-ink)] select-none">
              Системный анализ · Архитектура, STRIDE и цепочки риска
              {typeof card.systemAnalysis.auth_coverage_pct === 'number'
                ? ` (Auth: ${card.systemAnalysis.auth_coverage_pct}%)`
                : ''}
            </summary>
            <div className="mt-2 pt-2 border-t-2 border-[var(--color-line)] space-y-2 text-[var(--color-body-text)]">
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-3 gap-y-1 font-mono text-[11px]">
                {card.systemAnalysis.tech_stack && card.systemAnalysis.tech_stack.length > 0 && (
                  <div>
                    <dt className="inline text-[var(--color-muted-soft)]">Стек: </dt>
                    <dd className="inline text-[var(--color-ink)]">{card.systemAnalysis.tech_stack.join(', ')}</dd>
                  </div>
                )}
                {card.systemAnalysis.datastores && card.systemAnalysis.datastores.length > 0 && (
                  <div>
                    <dt className="inline text-[var(--color-muted-soft)]">БД: </dt>
                    <dd className="inline text-[var(--color-ink)]">{card.systemAnalysis.datastores.join(', ')}</dd>
                  </div>
                )}
                <div>
                  <dt className="inline text-[var(--color-muted-soft)]">API-маршруты: </dt>
                  <dd className="inline text-[var(--color-ink)]">
                    {card.systemAnalysis.endpoints_total ?? 0}
                    {typeof card.systemAnalysis.auth_coverage_pct === 'number'
                      ? ` · Auth ${card.systemAnalysis.auth_coverage_pct}%`
                      : ''}
                  </dd>
                </div>
                {card.systemAnalysis.stride_breakdown &&
                  Object.values(card.systemAnalysis.stride_breakdown).some((n) => n > 0) && (
                    <div className="sm:col-span-2">
                      <dt className="inline text-[var(--color-muted-soft)]">STRIDE: </dt>
                      <dd className="inline text-[var(--color-ink)]">
                        {Object.entries(card.systemAnalysis.stride_breakdown)
                          .filter(([, count]) => count > 0)
                          .map(([cat, count]) => `${cat} (${count})`)
                          .join(' · ')}
                      </dd>
                    </div>
                  )}
              </dl>

              {card.systemAnalysis.risk_chains && card.systemAnalysis.risk_chains.length > 0 && (
                <div className="space-y-1">
                  <div className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                    Цепочки риска (Blast Radius)
                  </div>
                  <ul className="space-y-1.5 list-disc pl-4">
                    {card.systemAnalysis.risk_chains.slice(0, 3).map((chain, idx) => (
                      <li key={idx} className="leading-snug">
                        <span className="font-mono text-[10.5px] text-[#ff7b66] mr-1">[{chain.severity}]</span>
                        <strong className="text-[var(--color-ink)] font-semibold">{chain.title}:</strong>{' '}
                        <span>{chain.steps.join(' → ')}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {card.systemAnalysis.remediation_roadmap && card.systemAnalysis.remediation_roadmap.length > 0 && (
                <div className="space-y-1">
                  <div className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
                    План системных исправлений
                  </div>
                  <ul className="space-y-0.5 list-disc pl-4 text-[11.5px]">
                    {card.systemAnalysis.remediation_roadmap.slice(0, 3).map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </details>
        )}

      {/* Auditor summary */}
      {card.summary && (
        <p className="text-[12px] text-[var(--color-muted-soft)] leading-relaxed border-t-2 border-[var(--color-line)] pt-2">
          {card.summary.slice(0, 320)}
          {card.summary.length > 320 ? '…' : ''}
        </p>
      )}

      {/* Downloadable Compliance PDF / MD Document Attachments */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {card.pdfUrl && (
          <a
            href={card.pdfUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="pixel-btn-snow min-h-8 px-3 py-1.5 font-mono text-[11.5px] inline-flex items-center gap-1.5"
          >
            <FileDown className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Compliance_Report.pdf</span>
          </a>
        )}
        {card.mdUrl && (
          <a
            href={card.mdUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="pixel-btn min-h-8 px-3 py-1.5 bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-[11.5px] inline-flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Markdown (.md)</span>
          </a>
        )}
        {card.canSelfHeal && (card.isRealRepo ? onAutoFixRepo : onTriggerSelfHeal) && (
          <button
            type="button"
            disabled={isHealing}
            onClick={() => {
              if (card.isRealRepo && onAutoFixRepo) {
                onAutoFixRepo(card.repoName);
              } else if (onTriggerSelfHeal) {
                onTriggerSelfHeal();
              }
            }}
            className="pixel-btn-emerald min-h-8 px-3 py-1.5 disabled:opacity-60 font-mono text-[11.5px] font-semibold inline-flex items-center gap-1.5 cursor-pointer"
          >
            {card.isRealRepo ? (
              <Wrench className="w-3.5 h-3.5" aria-hidden="true" />
            ) : (
              <HeartPulse className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            <span>
              {isHealing
                ? 'Патчу и коммичу…'
                : card.isRealRepo
                ? 'Исправить и закоммитить'
                : 'Self-Heal'}
            </span>
          </button>
        )}
        {onOpenFindingsDrawer && card.totalFindings > 0 && (
          <button
            type="button"
            onClick={onOpenFindingsDrawer}
            className="pixel-btn min-h-8 px-3 py-1.5 bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-[11.5px] inline-flex items-center gap-1.5 cursor-pointer"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Разбор ({card.totalFindings})</span>
          </button>
        )}
      </div>
    </div>
  );
}

function InlineVerifyCard({
  card,
  isPolling,
  checks,
  isCheckingNow,
  onCheckNow,
  onOpenAuthorshipDrawer,
}: {
  card: ChatVerifyCard;
  isPolling: boolean;
  checks: number;
  isCheckingNow: boolean;
  onCheckNow?: () => void;
  onOpenAuthorshipDrawer?: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(card.challengeCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="pixel-card mt-1.5 bg-[var(--color-canvas)] p-3.5 space-y-3 text-xs">
      {/* Repo + Code header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b-2 border-[var(--color-line)]">
        <div className="min-w-0">
          <div className="font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
            Авто-подтверждение авторства
          </div>
          <div className="font-mono text-xs font-semibold text-[var(--color-ink)] truncate">
            {card.repoName}
          </div>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          title="Скопировать код подтверждения"
          className="pixel-btn min-h-7 px-2 py-1 bg-[var(--color-paper)] font-mono text-[11px] text-[#ff7b66] inline-flex items-center gap-1.5 cursor-pointer"
        >
          <code>{card.challengeCode}</code>
          {copied ? (
            <Check className="w-3 h-3 text-[#47d18c]" aria-hidden="true" />
          ) : (
            <Copy className="w-3 h-3 text-[var(--color-muted-soft)]" aria-hidden="true" />
          )}
        </button>
      </div>

      {card.verified ? (
        <div className="border-2 border-[#47d18c] bg-[#47d18c]/15 px-3 py-2 flex items-center gap-2 font-mono text-xs text-[#5ee8a7]">
          <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>Авторство подтверждено! Запускаю аудит репозитория…</span>
        </div>
      ) : (
        <>
          {/* Step 1: 1-Click GitHub Commit Button (zero terminal!) */}
          <a
            href={card.verifyUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="pixel-btn-primary w-full min-h-10 px-3.5 py-2 font-mono text-xs font-semibold inline-flex items-center justify-center gap-2"
          >
            <span>1. Открыть GitHub и нажать «Commit changes»</span>
            <ExternalLink className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          </a>

          <p className="text-[12px] text-[var(--color-muted-soft)] leading-relaxed">
            Терминал не нужен: файл{' '}
            <code className="text-[var(--color-ink)]">{card.verifyFilename || 'verify.txt'}</code> и код уже
            заполнены. Просто нажми зелёную кнопку <strong className="text-[var(--color-ink)]">Commit changes</strong>{' '}
            на GitHub (или вставь код в описание репо About) и вернись сюда — скан стартует сам.
          </p>

          {/* Step 2: Live Automatic Background Check Indicator */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t-2 border-[var(--color-line)]">
            <div className="inline-flex items-center gap-1.5 font-mono text-[11.5px] text-[#56d4b2]">
              {isPolling || isCheckingNow ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" aria-hidden="true" />
                  <span>
                    Сама проверяю GitHub…{checks > 0 ? ` (${checks})` : ''}
                  </span>
                </>
              ) : (
                <span className="text-[var(--color-muted-soft)]">Готово к проверке</span>
              )}
            </div>

            <div className="flex items-center gap-1.5">
              {onCheckNow && (
                <button
                  type="button"
                  disabled={isCheckingNow}
                  onClick={onCheckNow}
                  className="pixel-btn min-h-7 px-2.5 py-1 bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={cn('w-3 h-3', isCheckingNow && 'animate-spin')} aria-hidden="true" />
                  <span>Проверить сейчас</span>
                </button>
              )}
              {onOpenAuthorshipDrawer && (
                <button
                  type="button"
                  onClick={onOpenAuthorshipDrawer}
                  className="pixel-btn min-h-7 px-2.5 py-1 bg-[var(--color-paper)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer"
                >
                  <KeyRound className="w-3 h-3" aria-hidden="true" />
                  <span>Token</span>
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function InlineCommitCard({
  card,
  messageId,
  isHealing,
  onCommitWithToken,
}: {
  card: ChatCommitCard;
  messageId: string;
  isHealing?: boolean;
  onCommitWithToken?: (repoName: string, opts?: { githubToken?: string; directCommit?: boolean; messageId?: string }) => void;
}) {
  const [token, setToken] = useState('');
  const [directCommit, setDirectCommit] = useState(Boolean(card.directCommit));

  return (
    <div className="pixel-card !border-[#47d18c] mt-1.5 bg-[var(--color-canvas)] p-3.5 space-y-3 text-xs">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b-2 border-[var(--color-line)]">
        <div className="min-w-0">
          <div className="font-mono text-[10.5px] uppercase tracking-wider text-[#47d18c] inline-flex items-center gap-1.5">
            <Wrench className="w-3 h-3 shrink-0" aria-hidden="true" />
            <span>Auto-Fix &amp; Commit</span>
          </div>
          <div className="font-mono text-xs font-semibold text-[var(--color-ink)] truncate">
            {card.repoName}
          </div>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[11px] tabular-nums shrink-0">
          <span className="px-2 py-0.5 bg-[#47d18c]/20 text-[#5ee8a7] border-2 border-[#47d18c] font-semibold">
            {card.beforeScore} ({card.beforeGrade}) → {card.afterScore} ({card.afterGrade})
          </span>
          <span className="px-2 py-0.5 bg-[var(--color-panel)] border-2 border-[var(--color-line)] text-[var(--color-muted-soft)]">
            фикс: {card.fixedCount}
          </span>
        </div>
      </div>

      {/* Verified Diffs */}
      {card.fixes.length > 0 && (
        <div className="space-y-2">
          {card.fixes.slice(0, 4).map((fix) => (
            <details
              key={fix.file_path}
              open={card.fixes.length <= 2}
              className="border-2 border-[#30436b] bg-[#080c16] overflow-hidden"
            >
              <summary className="px-3 py-1.5 font-mono text-[11px] text-[#eef6ff] flex items-center justify-between gap-2 cursor-pointer select-none bg-[#121829]">
                <span className="truncate">{fix.file_path}</span>
                <span className="text-[10.5px] text-[#47d18c] shrink-0">{fix.fixers.join(' · ')}</span>
              </summary>
              <pre className="p-2.5 overflow-x-auto text-[10.5px] leading-relaxed max-h-48">
                {fix.diff.split('\n').slice(0, 32).map((line, idx) => (
                  <div
                    key={idx}
                    className={
                      line.startsWith('+') && !line.startsWith('+++')
                        ? 'text-[#5ee8a7] bg-[#3fbf7f]/15'
                        : line.startsWith('-') && !line.startsWith('---')
                        ? 'text-[#ff8573] bg-[#e94a32]/15'
                        : line.startsWith('@@')
                        ? 'text-[#6ce4ff]'
                        : 'text-[#93add1]'
                    }
                  >
                    {line || ' '}
                  </div>
                ))}
              </pre>
            </details>
          ))}
        </div>
      )}

      {/* Commit Result OR 1-click GitHub Token Commit Action */}
      {card.committed ? (
        <div className="border-2 border-[#47d18c] bg-[#47d18c]/15 p-3 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs text-[#5ee8a7]">
            <span className="inline-flex items-center gap-1.5 font-semibold">
              <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
              <span>Закоммичено в GitHub</span>
            </span>
            <span className="text-[11px] text-[var(--color-ink)]">
              {card.branchName && <code>{card.branchName}</code>}
              {card.commitSha && <> · <code>{card.commitSha.slice(0, 7)}</code></>}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {card.pullRequestUrl && (
              <a
                href={card.pullRequestUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="pixel-btn-emerald min-h-8 px-3 py-1.5 font-mono text-[11.5px] font-semibold inline-flex items-center gap-1.5"
              >
                <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Открыть Pull Request</span>
                <ExternalLink className="w-3 h-3" aria-hidden="true" />
              </a>
            )}
            {card.commitUrl && (
              <a
                href={card.commitUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="pixel-btn min-h-8 px-3 py-1.5 bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-[11.5px] inline-flex items-center gap-1.5"
              >
                <GitCommitHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Открыть коммит</span>
                <ExternalLink className="w-3 h-3" aria-hidden="true" />
              </a>
            )}
          </div>
        </div>
      ) : card.needsToken && card.fixes.length > 0 && onCommitWithToken ? (
        <div className="pixel-panel bg-[var(--color-paper)] p-3 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[11.5px] text-[var(--color-ink)] font-semibold">
              Запушить эти патчи коммитом в GitHub
            </span>
            <a
              href={
                card.tokenCreateUrl ||
                'https://github.com/settings/tokens/new?scopes=repo&description=Commit+Guardian+Auto-Commit'
              }
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[11px] text-[#56d4b2] hover:underline inline-flex items-center gap-1"
            >
              <span>Создать Token (1 клик)</span>
              <ExternalLink className="w-3 h-3" aria-hidden="true" />
            </a>
          </div>

          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Вставь GitHub Token (ghp_... с правом repo) — не сохраняется на сервере"
            className="pixel-input w-full min-h-8 px-2.5 py-1.5 bg-[var(--color-canvas)] focus:border-[#47d18c] text-xs font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
          />

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex border-2 border-[var(--color-line)] p-0.5 bg-[var(--color-canvas)] font-mono text-[11px]">
              <button
                type="button"
                onClick={() => setDirectCommit(false)}
                className={cn(
                  'px-2 py-1 transition-colors cursor-pointer',
                  !directCommit
                    ? 'bg-[var(--color-panel)] text-[var(--color-ink)] font-semibold'
                    : 'text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                )}
              >
                Ветка + PR
              </button>
              <button
                type="button"
                onClick={() => setDirectCommit(true)}
                className={cn(
                  'px-2 py-1 transition-colors cursor-pointer',
                  directCommit
                    ? 'bg-[var(--color-panel)] text-[var(--color-ink)] font-semibold'
                    : 'text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                )}
              >
                Сразу в main
              </button>
            </div>

            <button
              type="button"
              disabled={!token.trim() || isHealing}
              onClick={() =>
                onCommitWithToken(card.repoName, {
                  githubToken: token.trim(),
                  directCommit,
                  messageId,
                })
              }
              className="pixel-btn-emerald min-h-8 px-3 py-1.5 disabled:opacity-45 font-mono text-[11.5px] font-semibold inline-flex items-center gap-1.5 cursor-pointer"
            >
              <GitCommitHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{isHealing ? 'Коммичу…' : 'Закоммитить в GitHub'}</span>
            </button>
          </div>
        </div>
      ) : card.commitMessage ? (
        <p className="font-mono text-[11.5px] text-[var(--color-muted-soft)] leading-relaxed">{card.commitMessage}</p>
      ) : null}
    </div>
  );
}

export function AiCopilotChat({
  messages,
  input,
  onInputChange,
  onSubmit,
  onQuickPrompt,
  onResetChat,
  onUploadZip,
  onTriggerSelfHeal,
  onAutoFixRepo,
  onOpenFindingsDrawer,
  onOpenAuthorshipDrawer,
  onCheckVerifyNow,
  pendingVerifyRepo,
  pendingVerifyChecks = 0,
  isCheckingVerify = false,
  companionMood = 'idle',
  motionPaused = false,
  isHealing,
  isTyping,
  isScanning,
  ollamaOnline,
  ollamaModel,
  activeTarget,
  className,
}: AiCopilotChatProps) {
  const prefersReducedMotion = useReducedMotion();
  const inputId = useId();
  const fileInputId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const [isDraggingZip, setIsDraggingZip] = useState(false);

  useEffect(() => {
    const container = logContainerRef.current;
    if (!container) return;
    container.scrollTo({ top: container.scrollHeight, behavior: prefersReducedMotion ? 'auto' : 'smooth' });
  }, [messages, isTyping, prefersReducedMotion]);

  // IME-safe Enter-to-submit (modern-web-guidance: ime-safe-enter-submit)
  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (e.nativeEvent.isComposing || e.keyCode === 229) {
        return;
      }
      if (input.trim() && !isTyping) {
        formRef.current?.requestSubmit();
      }
    }
  };

  return (
    <section
      aria-label="Чат с Aegis Orca"
      className={cn(
        'bg-[var(--color-canvas)] text-[var(--color-ink)] flex flex-col relative h-full min-h-0',
        className
      )}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDraggingZip(true);
      }}
      onDragLeave={() => setIsDraggingZip(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDraggingZip(false);
        const file = e.dataTransfer.files?.[0];
        if (file) onUploadZip(file);
      }}
    >
      {/* Slim Pixel Chat Header */}
      <div className="px-4 sm:px-5 py-2.5 border-b-2 border-[var(--color-line)] bg-[var(--color-paper)] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <OrcaMiniAvatar mood={companionMood} />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-sans text-sm font-semibold tracking-tight truncate">
                Aegis Orca
              </span>
              <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-[var(--color-muted-soft)]">
                <span
                  className={cn(
                    'w-2 h-2 shrink-0',
                    ollamaOnline ? 'bg-[#47d18c]' : 'bg-[#f0b541]'
                  )}
                  aria-hidden="true"
                />
                <span className="truncate">
                  {ollamaOnline ? ollamaModel : 'on-prem engine'}
                </span>
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {activeTarget && (
            <span className="hidden md:inline-block font-mono text-[11px] px-2 py-0.5 bg-[var(--color-panel)] border-2 border-[var(--color-line)] text-[var(--color-muted-soft)] truncate max-w-[180px]">
              {activeTarget}
            </span>
          )}
          <button
            type="button"
            onClick={onResetChat}
            className="pixel-btn min-h-8 px-2.5 py-1 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11.5px] inline-flex items-center gap-1 cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" aria-hidden="true" />
            <span>Новый чат</span>
          </button>
        </div>
      </div>

      {/* Pixel Christmas Eve Starry Sky + Gentle Snowfall Message Stream */}
      <div className="relative flex-1 min-h-0 flex flex-col pixel-sky-bg overflow-hidden">
        <PixelSnowfallLayer paused={motionPaused} />
        <div
          ref={logContainerRef}
          role="log"
          aria-live="polite"
          aria-relevant="additions"
          aria-label="Переписка с Aegis Orca"
          className="cg-scroll relative z-10 flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 pt-5 pb-4 flex flex-col gap-4"
        >
          {messages.map((msg) => {
            const isUser = msg.role === 'user';
            const isStreaming = msg.id === 'streaming' || msg.id === 'scan-status';
            const avatarMood: OrcaMood = msg.commitCard
              ? msg.commitCard.committed
                ? 'happy'
                : 'idle'
              : msg.verifyCard
              ? msg.verifyCard.verified
                ? 'happy'
                : 'blocked'
              : msg.content.startsWith('⛔')
              ? 'alert'
              : msg.auditCard && msg.auditCard.critical === 0 && msg.auditCard.high === 0
              ? 'happy'
              : msg.auditCard
              ? 'alert'
              : isStreaming
              ? 'scanning'
              : 'idle';

            const isPollingThisCard = Boolean(
              msg.verifyCard &&
                !msg.verifyCard.verified &&
                pendingVerifyRepo &&
                pendingVerifyRepo.toLowerCase() === msg.verifyCard.repoName.toLowerCase()
            );

            return (
              <motion.div
                key={msg.id}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.16, ease: 'easeOut' }}
                className={cn('flex items-end gap-2.5', isUser ? 'justify-end' : 'justify-start')}
              >
                {!isUser && <OrcaMiniAvatar mood={avatarMood} className="mb-0.5" />}
                <div
                  className={cn(
                    'max-w-[88%] sm:max-w-[78%] px-4 py-3 flex flex-col gap-1.5 border-2 shadow-[4px_4px_0_var(--pixel-shadow)]',
                    isUser
                      ? 'bg-[var(--color-raised)] border-[#e93e32] text-[var(--color-ink)]'
                      : 'bg-[var(--color-paper)] border-[var(--color-line-strong)] pixel-snow-cap text-[var(--color-body-text)]'
                  )}
                >
                  {msg.content && <FormattedBubbleContent content={msg.content} />}
                  {msg.verifyCard && (
                    <InlineVerifyCard
                      card={msg.verifyCard}
                      isPolling={isPollingThisCard}
                      checks={isPollingThisCard ? pendingVerifyChecks : 0}
                      isCheckingNow={isPollingThisCard && isCheckingVerify}
                      onCheckNow={
                        onCheckVerifyNow
                          ? () => onCheckVerifyNow(msg.verifyCard!.repoName, msg.verifyCard!.challengeCode)
                          : undefined
                      }
                      onOpenAuthorshipDrawer={onOpenAuthorshipDrawer}
                    />
                  )}
                  {msg.commitCard && (
                    <InlineCommitCard
                      card={msg.commitCard}
                      messageId={msg.id}
                      isHealing={isHealing}
                      onCommitWithToken={onAutoFixRepo}
                    />
                  )}
                  {msg.auditCard && (
                    <TelegramAuditCard
                      card={msg.auditCard}
                      onTriggerSelfHeal={onTriggerSelfHeal}
                      onAutoFixRepo={onAutoFixRepo}
                      onOpenFindingsDrawer={onOpenFindingsDrawer}
                      isHealing={isHealing}
                    />
                  )}
                  <div
                    className={cn(
                      'font-mono text-[11px] tabular-nums flex items-center gap-1.5 text-[var(--color-faint)]',
                      isUser ? 'justify-end' : 'justify-start'
                    )}
                  >
                    <span>{isUser ? 'you' : 'orca'} · {msg.timestamp}</span>
                    {isStreaming && (
                      <span
                        className="pixel-blink inline-block w-2 h-3 bg-[#e93e32]"
                        aria-label="печатает"
                      />
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
          <PixelWinterHorizon />
        </div>
      </div>

      {/* Crisp Pixel Prompt Chips */}
      <div className="px-4 sm:px-5 py-2 border-t-2 border-[var(--color-line)] flex flex-wrap gap-2 shrink-0 bg-[var(--color-paper)]">
        {QUICK_PROMPTS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            disabled={isTyping}
            onClick={() => onQuickPrompt(prompt)}
            className="pixel-btn text-xs font-sans px-3 py-1 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* 16-Bit Pixel Composer Bar */}
      <div className="p-3.5 sm:p-4 border-t-2 border-[var(--color-line)] shrink-0 bg-[var(--color-paper)]">
        <form
          ref={formRef}
          onSubmit={onSubmit}
          className="pixel-input flex items-end gap-2 focus-within:!border-[#56d4b2] bg-[var(--color-panel)] px-3 py-1.5 transition-colors"
        >
          <label htmlFor={inputId} className="visually-hidden">
            Сообщение для AI-ассистента или ссылка на GitHub
          </label>

          <input
            id={fileInputId}
            type="file"
            accept=".zip"
            className="visually-hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onUploadZip(file);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            disabled={isScanning}
            onClick={() => document.getElementById(fileInputId)?.click()}
            aria-label="Загрузить ZIP-архив кода"
            className="min-h-9 min-w-9 border-2 border-transparent hover:border-[var(--color-line-strong)] hover:bg-[var(--color-raised)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] flex items-center justify-center shrink-0 transition-colors cursor-pointer disabled:opacity-50"
          >
            <Paperclip className="w-4 h-4" aria-hidden="true" />
          </button>

          <div className="cg-autogrow flex-1 min-w-0 py-1.5" data-replicated-value={input}>
            <textarea
              id={inputId}
              rows={1}
              value={input}
              onChange={(e) => onInputChange(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Спроси AI о коде или вставь github.com/owner/repo..."
              className="bg-transparent text-[15px] text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none focus-visible:outline-none leading-[1.45]"
            />
          </div>

          <button
            type="submit"
            disabled={!input.trim() || isTyping}
            aria-label="Отправить сообщение"
            className="pixel-btn-primary min-h-9 min-w-9 disabled:opacity-35 flex items-center justify-center shrink-0 cursor-pointer"
          >
            <ArrowUp className="w-4 h-4" aria-hidden="true" />
          </button>
        </form>
      </div>

      {isDraggingZip && (
        <div className="absolute inset-0 bg-[var(--color-canvas)]/92 text-[var(--color-ink)] flex flex-col items-center justify-center gap-2 z-20 border-4 border-dashed border-[#56d4b2]">
          <Upload className="w-7 h-7 text-[#56d4b2]" aria-hidden="true" />
          <p className="font-mono text-sm">Отпусти .zip — проверю локально и удалю исходники</p>
        </div>
      )}
    </section>
  );
}

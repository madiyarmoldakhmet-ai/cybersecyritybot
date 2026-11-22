'use client';

import { FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import {
  ArrowUp,
  FileDown,
  FileText,
  GitBranch,
  HeartPulse,
  Paperclip,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
} from 'lucide-react';
import { cn } from '@/lib/utils';

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
  canSelfHeal?: boolean;
};

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  auditCard?: ChatAuditCard;
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
  onOpenFindingsDrawer?: () => void;
  isHealing?: boolean;
  isTyping: boolean;
  isScanning: boolean;
  ollamaOnline: boolean | null;
  ollamaModel: string;
  activeTarget: string;
  className?: string;
}

const QUICK_PROMPTS = [
  'Объясни критичные баги',
  'Оцени риск в тенге (КоАП РК)',
  'Самоисцеление и Git-секреты',
  'Как работает проверка авторства?',
];

function renderCodeSpans(text: string, keyPrefix: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return (
        <code
          key={`${keyPrefix}-c-${idx}`}
          className="font-mono text-[0.86em] px-1.5 py-0.5 rounded bg-[var(--color-canvas)] border border-[var(--color-line)] text-[var(--color-ink)] break-words"
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
          className="font-mono text-[0.86em] px-1.5 py-0.5 rounded bg-[var(--color-canvas)] border border-[var(--color-line)] text-[var(--color-ink)] break-words"
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
              className="font-mono text-xs p-3 rounded-lg overflow-x-auto bg-[#0a0a0a] border border-[#232323] text-[#d9f99d]"
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
  onOpenFindingsDrawer,
  isHealing,
}: {
  card: ChatAuditCard;
  onTriggerSelfHeal?: () => void;
  onOpenFindingsDrawer?: () => void;
  isHealing?: boolean;
}) {
  const isClean = card.critical === 0 && card.high === 0;
  return (
    <div className="mt-1.5 rounded-xl border border-[var(--color-line-strong)] bg-[var(--color-paper)] p-3.5 space-y-2.5 text-xs">
      {/* Header matching Telegram Bot _format_scan_summary */}
      <div className="flex items-start justify-between gap-2 pb-2 border-b border-[var(--color-line)]">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 font-medium text-[var(--color-ink)]">
            {isClean ? (
              <ShieldCheck className="w-4 h-4 text-[#3fbf7f] shrink-0" aria-hidden="true" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-[#e94a32] shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">{card.repoName}</span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10.5px] text-[var(--color-muted-soft)]">
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
            'font-mono text-xs font-semibold px-2 py-0.5 rounded-md border tabular-nums shrink-0',
            isClean
              ? 'bg-[#3fbf7f]/15 text-[#3fbf7f] border-[#3fbf7f]/35'
              : 'bg-[#e94a32]/15 text-[#ff735d] border-[#e94a32]/35'
          )}
        >
          {card.score ?? '—'}/100 ({card.grade ?? '—'})
        </div>
      </div>

      {/* Severity Counts */}
      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] tabular-nums">
        <span className="text-[var(--color-muted-soft)]">Находок: <b className="text-[var(--color-ink)]">{card.totalFindings}</b></span>
        <span className="px-1.5 py-0.5 rounded bg-[#e94a32]/15 text-[#ff735d]">CRIT {card.critical}</span>
        <span className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400">HIGH {card.high}</span>
        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400">MED {card.medium}</span>
        <span className="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-400">LOW {card.low}</span>
      </div>

      {/* Financial Risk */}
      {card.riskKzt && card.riskKzt > 0 ? (
        <div className="px-2.5 py-1.5 rounded-lg bg-[#e94a32]/10 border border-[#e94a32]/30 font-mono text-[11px] text-[#ff735d]">
          Риск (ст. 79 КоАП РК): <b>до {formatKztInline(card.riskKzt)}</b>
        </div>
      ) : null}

      {/* Top Findings list */}
      {card.topFindings && card.topFindings.length > 0 && (
        <div className="space-y-1">
          <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--color-muted-soft)]">
            Топ находок
          </div>
          <ol className="space-y-1">
            {card.topFindings.slice(0, 5).map((f, i) => (
              <li key={i} className="text-[11.5px] leading-snug text-[var(--color-body-text)]">
                <span className="font-mono text-[10px] text-[#ff735d] mr-1">[{f.severity}]</span>
                <span className="text-[var(--color-ink)]">{f.title}</span>{' '}
                <code className="font-mono text-[10px] text-[var(--color-muted-soft)]">{f.location}</code>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Auditor summary */}
      {card.summary && (
        <p className="text-[11.5px] text-[var(--color-muted-soft)] leading-relaxed border-t border-[var(--color-line)] pt-2">
          {card.summary.slice(0, 320)}
          {card.summary.length > 320 ? '…' : ''}
        </p>
      )}

      {/* Downloadable Compliance PDF / MD Document Attachments (1:1 like Telegram reply_document) */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {card.pdfUrl && (
          <a
            href={card.pdfUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="min-h-8 px-3 py-1.5 rounded-lg bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-[11px] inline-flex items-center gap-1.5 transition-colors"
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
            className="min-h-8 px-3 py-1.5 rounded-lg border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] bg-[var(--color-panel)] text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1.5 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Markdown (.md)</span>
          </a>
        )}
        {card.canSelfHeal && onTriggerSelfHeal && (
          <button
            type="button"
            disabled={isHealing}
            onClick={onTriggerSelfHeal}
            className="min-h-8 px-3 py-1.5 rounded-lg bg-[#3fbf7f] hover:bg-[#34a96e] text-[#09120d] disabled:opacity-60 font-mono text-[11px] font-semibold inline-flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <HeartPulse className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{isHealing ? 'Исцеляю...' : 'Self-Heal'}</span>
          </button>
        )}
        {onOpenFindingsDrawer && card.totalFindings > 0 && (
          <button
            type="button"
            onClick={onOpenFindingsDrawer}
            className="min-h-8 px-3 py-1.5 rounded-lg border border-[var(--color-line-strong)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Разбор ({card.totalFindings})</span>
          </button>
        )}
      </div>
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
  onOpenFindingsDrawer,
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
      {/* Slim Chat Header */}
      <div className="px-4 sm:px-5 py-2.5 border-b border-[var(--color-line)] bg-[var(--color-paper)] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/mascot/orca_idle.webp"
            alt=""
            width={28}
            height={28}
            className="w-7 h-7 rounded-full object-cover border border-[var(--color-line-strong)] shrink-0 bg-[#0f0f12]"
          />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-sans text-sm font-medium tracking-tight truncate">
                Aegis Orca
              </span>
              <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-[var(--color-muted-soft)]">
                <span
                  className={cn(
                    'w-1.5 h-1.5 rounded-full',
                    ollamaOnline ? 'bg-[#3fbf7f]' : 'bg-[#e8a33d]'
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
            <span className="hidden md:inline-block font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--color-panel)] border border-[var(--color-line)] text-[var(--color-muted-soft)] truncate max-w-[180px]">
              {activeTarget}
            </span>
          )}
          <button
            type="button"
            onClick={onResetChat}
            className="min-h-8 px-2.5 py-1 rounded-full border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1 transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" aria-hidden="true" />
            <span>Новый чат</span>
          </button>
        </div>
      </div>

      {/* Message Stream */}
      <div
        ref={logContainerRef}
        role="log"
        aria-live="polite"
        aria-relevant="additions"
        aria-label="Переписка с Aegis Orca"
        className="cg-scroll flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 py-4 space-y-3.5 prtner-dots"
      >
        {messages.map((msg) => {
          const isUser = msg.role === 'user';
          const isStreaming = msg.id === 'streaming' || msg.id === 'scan-status';
          const avatarSrc = msg.content.startsWith('⛔')
            ? '/mascot/orca_alert.webp'
            : msg.auditCard && msg.auditCard.critical === 0 && msg.auditCard.high === 0
            ? '/mascot/orca_happy.webp'
            : msg.auditCard
            ? '/mascot/orca_alert.webp'
            : isStreaming
            ? '/mascot/orca_scan.webp'
            : '/mascot/orca_idle.webp';

          return (
            <motion.div
              key={msg.id}
              initial={prefersReducedMotion ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
              className={cn('flex items-end gap-2.5', isUser ? 'justify-end' : 'justify-start')}
            >
              {!isUser && (
                /* eslint-disable-next-line @next/next/no-img-element */
                <img
                  src={avatarSrc}
                  alt=""
                  width={28}
                  height={28}
                  className="w-7 h-7 rounded-full object-cover border border-[var(--color-line-strong)] shrink-0 mb-0.5 bg-[#0f0f12]"
                />
              )}
              <div
                className={cn(
                  'max-w-[88%] sm:max-w-[78%] px-4 py-3 flex flex-col gap-1.5 border shadow-xs',
                  isUser
                    ? 'bg-[var(--color-raised)] border-[var(--color-line-strong)] text-[var(--color-ink)] rounded-2xl rounded-br-sm'
                    : 'bg-[var(--color-paper)] border-[var(--color-line)] text-[var(--color-body-text)] rounded-2xl rounded-bl-sm'
                )}
              >
                {msg.content && <FormattedBubbleContent content={msg.content} />}
                {msg.auditCard && (
                  <TelegramAuditCard
                    card={msg.auditCard}
                    onTriggerSelfHeal={onTriggerSelfHeal}
                    onOpenFindingsDrawer={onOpenFindingsDrawer}
                    isHealing={isHealing}
                  />
                )}
                <div
                  className={cn(
                    'font-mono text-[10.5px] tabular-nums flex items-center gap-1.5 text-[var(--color-faint)]',
                    isUser ? 'justify-end' : 'justify-start'
                  )}
                >
                  <span>{isUser ? 'you' : 'orca'} · {msg.timestamp}</span>
                  {isStreaming && (
                    <span
                      className="inline-block w-1.5 h-3 bg-[#e94a32] animate-pulse"
                      aria-label="печатает"
                    />
                  )}
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Minimal Prompt Chips */}
      <div className="px-5 py-2 border-t border-[var(--color-line)] flex flex-wrap gap-1.5 shrink-0 bg-[var(--color-paper)]">
        {QUICK_PROMPTS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            disabled={isTyping}
            onClick={() => onQuickPrompt(prompt)}
            className="text-xs font-sans px-3 py-1 rounded-full border border-[var(--color-line)] bg-[var(--color-panel)] hover:border-[#e94a32] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] transition-colors cursor-pointer disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Sleek Dark Pill Composer */}
      <div className="p-4 border-t border-[var(--color-line)] shrink-0 bg-[var(--color-paper)]">
        <form
          ref={formRef}
          onSubmit={onSubmit}
          className="flex items-end gap-2 rounded-2xl border border-[var(--color-line-strong)] focus-within:border-[#e94a32] bg-[var(--color-panel)] px-3 py-1.5 transition-colors"
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
            className="min-h-9 min-w-9 rounded-full hover:bg-[var(--color-raised)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] flex items-center justify-center shrink-0 transition-colors cursor-pointer disabled:opacity-50"
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
              className="bg-transparent text-[15px] text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none leading-[1.45]"
            />
          </div>

          <button
            type="submit"
            disabled={!input.trim() || isTyping}
            aria-label="Отправить сообщение"
            className="min-h-9 min-w-9 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] disabled:opacity-35 text-[var(--color-canvas)] hover:text-white flex items-center justify-center shrink-0 transition-colors cursor-pointer"
          >
            <ArrowUp className="w-4 h-4" aria-hidden="true" />
          </button>
        </form>
      </div>

      {isDraggingZip && (
        <div className="absolute inset-0 bg-[var(--color-canvas)]/92 text-[var(--color-ink)] flex flex-col items-center justify-center gap-2 z-20 border-2 border-dashed border-[#e94a32]">
          <Upload className="w-7 h-7 text-[#e94a32]" aria-hidden="true" />
          <p className="font-mono text-sm">Отпусти .zip — проверю локально и удалю исходники</p>
        </div>
      )}
    </section>
  );
}

'use client';

import { cn } from '@/lib/utils';
import { Download, FileText } from 'lucide-react';

interface SecurityScoreProps {
  score: number | null;
  grade?: string | null;
  elapsedTime: number;
  vulnerabilities: number;
  isScanning?: boolean;
  reportPdfUrl?: string | null;
  reportMdUrl?: string | null;
  className?: string;
}

export function SecurityScore({
  score,
  grade,
  elapsedTime,
  vulnerabilities,
  isScanning = false,
  reportPdfUrl,
  reportMdUrl,
  className,
}: SecurityScoreProps) {
  const hasScore = score !== null && !Number.isNaN(score);
  const displayDigits = isScanning ? 'SCAN' : hasScore ? `${score}` : '--';
  const isSafe = hasScore && score >= 80;
  const isWarning = hasScore && score >= 50 && score < 80;

  const verdictText = isScanning
    ? 'analyzing'
    : !hasScore
    ? 'standby'
    : isSafe
    ? 'passed'
    : isWarning
    ? 'patch_recommended'
    : 'blocking_risk';

  const digitColor = !hasScore
    ? 'text-[var(--color-muted-soft)]'
    : isSafe
    ? 'text-[#47d18c]'
    : isWarning
    ? 'text-[#f0b541]'
    : 'text-[#ff7b66]';

  const barFillColor = !hasScore
    ? 'bg-[var(--color-line)]'
    : isSafe
    ? 'bg-[#47d18c]'
    : isWarning
    ? 'bg-[#f0b541]'
    : 'bg-[#e94a32]';

  const filledBlocks = hasScore ? Math.max(0, Math.min(10, Math.round(score / 10))) : 0;

  return (
    <div
      className={cn(
        'pixel-card bg-[var(--color-panel)] p-4 space-y-3',
        className
      )}
    >
      <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
        <span>AUDIT · VERDICT</span>
        <span className="px-1.5 py-0.5 border border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-moon)]">
          GRADE {grade || '—'}
        </span>
      </div>

      <div className="flex items-baseline gap-2.5">
        <span className={cn('font-pixel text-3xl sm:text-4xl leading-none tabular-nums', digitColor)}>
          {displayDigits}
        </span>
        <span className="font-mono text-xs text-[var(--color-faint)] tabular-nums">/ 100</span>
      </div>

      {/* 10-Block Stepped 16-Bit Pixel HP/Security Gauge */}
      <div className="grid grid-cols-10 gap-1 pt-0.5" aria-hidden="true">
        {Array.from({ length: 10 }).map((_, idx) => (
          <span
            key={idx}
            className={cn(
              'h-2.5 border border-[var(--color-line-strong)]',
              idx < filledBlocks ? barFillColor : 'bg-[var(--color-canvas)]'
            )}
          />
        ))}
      </div>

      <div className="border-t-2 border-[var(--color-line)] pt-2.5 space-y-1 font-mono text-xs tabular-nums">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">decision</span>
          <span className={hasScore ? (isSafe ? 'text-[#47d18c]' : 'text-[#ff7b66]') : 'text-[var(--color-muted-soft)]'}>
            {verdictText}
          </span>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">findings</span>
          <span className="text-[var(--color-ink)]">{vulnerabilities}</span>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">duration</span>
          <span className="text-[var(--color-ink)]">{elapsedTime.toFixed(2)} s</span>
        </div>
      </div>

      {reportPdfUrl && (
        <div className="flex flex-wrap gap-2 pt-1">
          <a
            href={reportPdfUrl}
            target="_blank"
            rel="noreferrer"
            className="pixel-btn-snow flex-1 min-h-8 px-3 py-1.5 font-mono text-xs inline-flex items-center justify-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>PDF-отчёт</span>
          </a>
          {reportMdUrl && (
            <a
              href={reportMdUrl}
              target="_blank"
              rel="noreferrer"
              className="pixel-btn min-h-8 px-3 py-1.5 bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-xs inline-flex items-center justify-center gap-1"
            >
              <FileText className="w-3.5 h-3.5" aria-hidden="true" />
              <span>MD</span>
            </a>
          )}
        </div>
      )}
    </div>
  );
}

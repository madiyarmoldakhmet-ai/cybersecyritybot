'use client';

import { cn } from '@/lib/utils';
import { FileText, Download } from 'lucide-react';

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

  const scoreStatusLabel = isScanning
    ? 'Выполняется аудит...'
    : !hasScore
    ? 'Ожидание запуска'
    : isSafe
    ? 'Пройден порог B2B'
    : isWarning
    ? 'Нужен патч'
    : 'Блокирующий риск';

  const digitColor = isScanning
    ? 'text-[#e94a32]'
    : !hasScore
    ? 'text-[#e94a32]'
    : isSafe
    ? 'text-emerald-400'
    : isWarning
    ? 'text-amber-400'
    : 'text-[#e94a32]';

  return (
    <div
      className={cn(
        'bg-[#e94a32] text-[#141414] border border-[#242424] p-5 flex flex-col justify-between gap-4',
        className
      )}
    >
      <div className="flex items-baseline justify-between gap-2 pb-3 border-b border-black/15">
        <span className="font-serif text-2xl tracking-tight leading-none text-[#141414]">Score</span>
        <span className="font-mono text-xs uppercase tracking-wider text-[#141414]/80">
          Табло и вердикт
        </span>
      </div>

      {/* Inner matte obsidian HUD styled after the prtner.ai Pixel scoreboard card */}
      <div className="bg-[#111111] text-[#ededed] rounded-xl p-4 border border-black/30 flex flex-col gap-3">
        <div className="flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-[#8f8f8f]">
          <span>AEGIS · SCORE</span>
          <span>GRADE {grade || '—'}</span>
        </div>

        <div className="flex items-baseline gap-2.5 py-1">
          <span
            className={cn(
              'font-pixel text-5xl sm:text-6xl leading-none tracking-tight tabular-nums',
              digitColor
            )}
          >
            {displayDigits}
          </span>
          <span className="font-mono text-sm text-[#8f8f8f] tabular-nums">/ 100</span>
        </div>

        <div className="border-t border-[#242424] pt-2.5 space-y-1.5 font-mono text-xs tabular-nums">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[#8f8f8f]">СТАТУС</span>
            <span className="text-[#ededed]">{scoreStatusLabel}</span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[#8f8f8f]">НАХОДКИ</span>
            <span className="text-[#ededed]">{vulnerabilities}</span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[#8f8f8f]">ЛАТЕНТНОСТЬ</span>
            <span className="text-[#ededed]">{elapsedTime.toFixed(2)} s</span>
          </div>
        </div>
      </div>

      {reportPdfUrl ? (
        <div className="flex flex-wrap gap-2">
          <a
            href={reportPdfUrl}
            target="_blank"
            rel="noreferrer"
            className="flex-1 min-h-9 px-3 py-2 bg-[#141414] hover:bg-black text-[#faf9f5] font-mono text-xs uppercase tracking-wider inline-flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>PDF-отчёт</span>
          </a>
          {reportMdUrl && (
            <a
              href={reportMdUrl}
              target="_blank"
              rel="noreferrer"
              className="min-h-9 px-3 py-2 bg-black/15 hover:bg-black/25 text-[#141414] font-mono text-xs uppercase tracking-wider inline-flex items-center justify-center gap-1 transition-colors"
            >
              <FileText className="w-3.5 h-3.5" aria-hidden="true" />
              <span>MD</span>
            </a>
          )}
        </div>
      ) : (
        <div className="font-mono text-[11px] uppercase tracking-wider text-[#141414]/85 flex items-center justify-between">
          <span>COMPLIANCE REPORT</span>
          <span>PDF + MARKDOWN</span>
        </div>
      )}
    </div>
  );
}

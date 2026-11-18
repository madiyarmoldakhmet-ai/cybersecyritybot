'use client';

import { cn } from '@/lib/utils';

interface MetricsDashboardProps {
  scannedFiles: number;
  totalFiles: number;
  vulnerabilities: number;
  elapsedTime: number;
  ollamaOnline?: boolean | null;
  ollamaModel?: string;
  isScanning?: boolean;
  className?: string;
}

export function MetricsDashboard({
  scannedFiles,
  totalFiles,
  vulnerabilities,
  elapsedTime,
  ollamaOnline,
  ollamaModel,
  isScanning = false,
  className,
}: MetricsDashboardProps) {
  const progress = totalFiles > 0 ? Math.min(100, (scannedFiles / totalFiles) * 100) : isScanning ? 40 : 0;

  return (
    <div
      className={cn(
        'grid grid-cols-2 sm:grid-cols-4 border border-[var(--color-line)] bg-[var(--color-line)] gap-px',
        className
      )}
    >
      <MetricCell
        code="01 · ФАЙЛЫ"
        value={totalFiles > 0 ? `${scannedFiles}/${totalFiles}` : `${scannedFiles || 0}`}
        meta={isScanning ? 'сканирую дерево' : 'локальный скан'}
        progress={isScanning || totalFiles > 0 ? progress : undefined}
      />
      <MetricCell
        code="02 · НАХОДКИ"
        value={`${vulnerabilities}`}
        meta={vulnerabilities > 0 ? 'требуют патча' : 'чистый контур'}
        accent={vulnerabilities > 0}
      />
      <MetricCell
        code="03 · ВРЕМЯ"
        value={`${elapsedTime.toFixed(1).replace(/\.0$/, '')} c`}
        meta="без отправки кода"
      />
      <MetricCell
        code="04 · ДВИЖОК ИИ"
        value={ollamaOnline ? 'ONLINE' : 'STANDBY'}
        meta={ollamaModel || 'qwen2.5-coder:14b'}
        highlight={Boolean(ollamaOnline)}
      />
    </div>
  );
}

interface MetricCellProps {
  code: string;
  value: string;
  meta: string;
  progress?: number;
  accent?: boolean;
  highlight?: boolean;
}

function MetricCell({ code, value, meta, progress, accent, highlight }: MetricCellProps) {
  return (
    <div className="bg-[var(--color-paper)] p-3.5 sm:p-4 relative flex flex-col justify-between gap-2 min-w-0">
      {progress !== undefined && (
        <div
          className="absolute bottom-0 left-0 h-0.5 bg-[#e94a32] transition-[width] duration-300"
          style={{ width: `${progress}%` }}
        />
      )}
      <div className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)] truncate">
        {code}
      </div>
      <div
        className={cn(
          'font-mono text-xl sm:text-2xl font-medium tracking-tight tabular-nums truncate',
          accent ? 'text-[#e94a32]' : highlight ? 'text-emerald-500' : 'text-[var(--color-ink)]'
        )}
      >
        {value}
      </div>
      <div className="font-mono text-[11px] text-[var(--color-muted-soft)] truncate">{meta}</div>
    </div>
  );
}

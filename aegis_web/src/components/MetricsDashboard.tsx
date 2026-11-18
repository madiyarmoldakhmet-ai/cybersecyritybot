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
  return (
    <div
      className={cn(
        'rounded-lg border border-[var(--color-line)] bg-[var(--color-paper)] px-3 py-2.5 font-mono text-xs space-y-1.5 tabular-nums',
        className
      )}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[var(--color-muted-soft)]">files</span>
        <span className="text-[var(--color-ink)]">
          {totalFiles > 0 ? `${scannedFiles}/${totalFiles}` : `${scannedFiles || 0}`}
          {isScanning ? ' (scanning)' : ''}
        </span>
      </div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[var(--color-muted-soft)]">engine</span>
        <span className={ollamaOnline ? 'text-[#3fbf7f]' : 'text-[var(--color-ink)]'}>
          {ollamaModel || 'qwen2.5-coder:14b'} · {ollamaOnline ? 'online' : 'standby'}
        </span>
      </div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[var(--color-muted-soft)]">findings</span>
        <span className={vulnerabilities > 0 ? 'text-[#e94a32]' : 'text-[#3fbf7f]'}>
          {vulnerabilities}
        </span>
      </div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[var(--color-muted-soft)]">leakage</span>
        <span className="text-[#3fbf7f]">0 bytes · {elapsedTime.toFixed(1)}s</span>
      </div>
    </div>
  );
}

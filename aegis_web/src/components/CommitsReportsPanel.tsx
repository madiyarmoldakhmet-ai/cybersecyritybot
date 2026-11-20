'use client';

import { FormEvent, useState } from 'react';
import {
  ExternalLink,
  FileDown,
  FileText,
  GitBranch,
  GitCommitHorizontal,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export type RepoCommit = {
  sha: string;
  short: string;
  author: string;
  date: string;
  subject: string;
};

export type AuditHistoryItem = {
  created_at: string;
  status: string;
  repo_name: string;
  commit_sha: string;
  branch: string;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  ai_seconds?: number | null;
  ai_generated?: number;
  report_name?: string | null;
  pdf_url?: string | null;
  md_url?: string | null;
};

export type ReportsFeedData = {
  total_scans: number;
  failed_scans: number;
  critical_found: number;
  high_found: number;
  total_findings: number;
  repos_monitored: number;
  avg_scan_seconds: number | null;
  appeals_count: number;
  audits: AuditHistoryItem[];
};

interface CommitsReportsPanelProps {
  feed: ReportsFeedData | null;
  loadingFeed: boolean;
  onRefreshFeed: () => void;
  activeCommits: RepoCommit[];
  activeRepoName: string;
  ghostCommitShas: Set<string>;
  isScanning: boolean;
  onScanRepo: (repoUrl: string) => void;
  onDemoScan: () => void;
}

function formatUtcShort(iso: string): string {
  if (!iso) return '—';
  return iso.replace('T', ' ').slice(5, 16);
}

export function CommitsReportsPanel({
  feed,
  loadingFeed,
  onRefreshFeed,
  activeCommits,
  activeRepoName,
  ghostCommitShas,
  isScanning,
  onScanRepo,
  onDemoScan,
}: CommitsReportsPanelProps) {
  const [quickRepo, setQuickRepo] = useState('');

  const handleQuickSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!quickRepo.trim() || isScanning) return;
    onScanRepo(quickRepo.trim());
    setQuickRepo('');
  };

  const audits = feed?.audits ?? [];

  return (
    <div className="space-y-4 flex-1 flex flex-col min-h-0">
      {/* Quick Repo / Commit Audit Bar (1:1 like Telegram Bot input) */}
      <form onSubmit={handleQuickSubmit} className="space-y-2">
        <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
          <span>КОММИТЫ И ОТЧЁТЫ · LIVE</span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onRefreshFeed}
              disabled={loadingFeed}
              title="Обновить список отчётов"
              className="hover:text-[var(--color-ink)] transition-colors inline-flex items-center gap-1 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={cn('w-3 h-3', loadingFeed && 'animate-spin')} aria-hidden="true" />
              <span>Обновить</span>
            </button>
            <a
              href="/dashboard"
              className="hover:text-[var(--color-ink)] transition-colors inline-flex items-center gap-1"
            >
              <span>/dashboard</span>
              <ExternalLink className="w-3 h-3" aria-hidden="true" />
            </a>
          </div>
        </div>

        <div className="flex gap-1.5">
          <label htmlFor="cg-quick-repo" className="visually-hidden">
            GitHub репозиторий для проверки коммитов
          </label>
          <input
            id="cg-quick-repo"
            type="text"
            value={quickRepo}
            onChange={(e) => setQuickRepo(e.target.value)}
            placeholder="owner/repo или github.com/..."
            disabled={isScanning}
            className="flex-1 min-w-0 min-h-9 px-3 py-1.5 rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] focus:border-[#e94a32] text-xs font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
          />
          <button
            type="submit"
            disabled={isScanning || !quickRepo.trim()}
            className="min-h-9 px-3 rounded-lg bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-45 font-mono text-xs inline-flex items-center gap-1 transition-colors cursor-pointer shrink-0"
          >
            <Search className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Скан</span>
          </button>
        </div>
      </form>

      {/* Compact Live KPI Strip from SQLite */}
      <div className="grid grid-cols-4 gap-1.5 font-mono">
        <div className="rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] px-2.5 py-2">
          <div className="text-[10px] text-[var(--color-muted-soft)]">АУДИТОВ</div>
          <div className="text-sm font-semibold tabular-nums text-[var(--color-ink)]">
            {feed?.total_scans ?? 0}
          </div>
        </div>
        <div className="rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] px-2.5 py-2">
          <div className="text-[10px] text-[var(--color-muted-soft)]">CRIT</div>
          <div className="text-sm font-semibold tabular-nums text-[#ff735d]">
            {feed?.critical_found ?? 0}
          </div>
        </div>
        <div className="rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] px-2.5 py-2">
          <div className="text-[10px] text-[var(--color-muted-soft)]">FP</div>
          <div className="text-sm font-semibold tabular-nums text-[#3fbf7f]">
            {feed?.appeals_count ?? 0}
          </div>
        </div>
        <div className="rounded-lg bg-[var(--color-panel)] border border-[var(--color-line)] px-2.5 py-2">
          <div className="text-[10px] text-[var(--color-muted-soft)]">СРЕДН.</div>
          <div className="text-sm font-semibold tabular-nums text-[var(--color-ink)]">
            {feed?.avg_scan_seconds != null ? `${feed.avg_scan_seconds.toFixed(1)}с` : '—'}
          </div>
        </div>
      </div>

      {/* Real Git Commits of Currently Scanned Repository */}
      {activeCommits.length > 0 && (
        <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-3 space-y-2">
          <div className="flex items-center justify-between gap-2 font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
            <span className="inline-flex items-center gap-1.5 truncate">
              <GitCommitHorizontal className="w-3.5 h-3.5 text-[#e94a32] shrink-0" aria-hidden="true" />
              <span className="truncate">Коммиты: {activeRepoName}</span>
            </span>
            <span className="tabular-nums shrink-0">{activeCommits.length}</span>
          </div>
          <ul className="space-y-1.5 max-h-[140px] overflow-y-auto cg-scroll pr-1">
            {activeCommits.slice(0, 6).map((c) => {
              const isGhost = ghostCommitShas.has(c.short) || ghostCommitShas.has(c.sha);
              return (
                <li
                  key={c.sha}
                  className={cn(
                    'rounded-lg px-2.5 py-1.5 border text-xs flex flex-col gap-0.5',
                    isGhost
                      ? 'border-[#e94a32]/50 bg-[#e94a32]/10'
                      : 'border-[var(--color-line)] bg-[var(--color-paper)]'
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <code className="font-mono text-[10.5px] text-[#e94a32] shrink-0">{c.short}</code>
                      <span className="text-[var(--color-ink)] truncate font-medium">{c.subject}</span>
                    </div>
                    {isGhost && (
                      <span className="font-mono text-[9.5px] px-1.5 py-0.5 rounded bg-[#e94a32]/20 text-[#ff735d] shrink-0">
                        GHOST SECRET
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--color-muted-soft)] flex items-center justify-between gap-2">
                    <span className="truncate">{c.author}</span>
                    <span className="shrink-0">{c.date.slice(0, 10)}</span>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* Persisted Audited Commits & Downloadable Compliance PDF / MD Reports */}
      <div className="flex-1 min-h-0 flex flex-col rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] overflow-hidden">
        <div className="px-3 py-2 border-b border-[var(--color-line)] flex items-center justify-between font-mono text-[10.5px] uppercase tracking-wider text-[var(--color-muted-soft)]">
          <span>Журнал коммитов и PDF-отчётов</span>
          <span className="tabular-nums">{audits.length}</span>
        </div>

        {audits.length > 0 ? (
          <ul className="divide-y divide-[var(--color-line)] overflow-y-auto cg-scroll max-h-[300px]">
            {audits.map((a, idx) => {
              const hasRisk = a.status !== 'failed' && (a.critical > 0 || a.high > 0);
              const isClean = a.status !== 'failed' && a.critical === 0 && a.high === 0;
              return (
                <li
                  key={`${a.commit_sha}-${a.created_at}-${idx}`}
                  className="px-3 py-2.5 hover:bg-[var(--color-raised)]/60 transition-colors space-y-1.5"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        {hasRisk ? (
                          <ShieldAlert className="w-3.5 h-3.5 text-[#ff735d] shrink-0" aria-hidden="true" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5 text-[#3fbf7f] shrink-0" aria-hidden="true" />
                        )}
                        <span className="font-mono text-xs font-medium text-[var(--color-ink)] truncate">
                          {a.repo_name}
                        </span>
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10.5px] text-[var(--color-muted-soft)]">
                        <span className="inline-flex items-center gap-0.5">
                          <GitBranch className="w-3 h-3" aria-hidden="true" />
                          {a.branch || 'main'}
                        </span>
                        <code className="text-[var(--color-body-text)]">{(a.commit_sha || '').slice(0, 8)}</code>
                        <span>{formatUtcShort(a.created_at)}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      {a.pdf_url && (
                        <a
                          href={a.pdf_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="min-h-7 px-2 py-1 rounded-md bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-[10px] inline-flex items-center gap-1 transition-colors"
                        >
                          <FileDown className="w-3 h-3" aria-hidden="true" />
                          <span>PDF</span>
                        </a>
                      )}
                      {a.md_url && (
                        <a
                          href={a.md_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="min-h-7 px-2 py-1 rounded-md border border-[var(--color-line-strong)] hover:border-[var(--color-ink)] bg-[var(--color-paper)] text-[var(--color-ink)] font-mono text-[10px] inline-flex items-center gap-1 transition-colors"
                        >
                          <FileText className="w-3 h-3" aria-hidden="true" />
                          <span>MD</span>
                        </a>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-2 font-mono text-[10.5px] tabular-nums">
                    <div className="flex items-center gap-1.5">
                      <span className={cn('px-1.5 py-0.5 rounded', a.critical ? 'bg-[#e94a32]/15 text-[#ff735d]' : 'text-[var(--color-faint)]')}>
                        C:{a.critical}
                      </span>
                      <span className={cn('px-1.5 py-0.5 rounded', a.high ? 'bg-orange-500/15 text-orange-400' : 'text-[var(--color-faint)]')}>
                        H:{a.high}
                      </span>
                      <span className={cn('px-1.5 py-0.5 rounded', a.medium ? 'bg-amber-500/15 text-amber-400' : 'text-[var(--color-faint)]')}>
                        M:{a.medium}
                      </span>
                      <span className="text-[var(--color-muted-soft)]">Σ {a.total_findings}</span>
                    </div>
                    <span
                      className={cn(
                        'px-2 py-0.5 rounded-full text-[10px]',
                        a.status === 'failed'
                          ? 'bg-neutral-500/15 text-[var(--color-muted-soft)]'
                          : isClean
                          ? 'bg-[#3fbf7f]/15 text-[#3fbf7f]'
                          : 'bg-[#e94a32]/15 text-[#ff735d]'
                      )}
                    >
                      {a.status === 'failed' ? 'ошибка' : isClean ? 'чисто' : 'риск'}
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-5 gap-3">
            <p className="font-mono text-xs text-[var(--color-muted-soft)]">
              Пока нет проверенных коммитов. Отправь ссылку на GitHub, .zip или нажми «Демо-аудит».
            </p>
            <button
              type="button"
              onClick={onDemoScan}
              disabled={isScanning}
              className="min-h-8 px-3.5 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Запустить Демо KZ</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Banknote, CheckCircle2, Hand, HeartPulse, History, Undo2 } from 'lucide-react';
import { cn } from '@/lib/utils';

// ---------- Types shared with page.tsx ----------

export type FindingRisk = {
  finding_id: string;
  title: string;
  location: string;
  severity: string;
  category: string;
  category_label: string;
  risk_kzt: number;
};

export type FinancialRisk = {
  total_kzt: number;
  regulatory_kzt: number;
  incident_kzt: number;
  legal_basis: string;
  headline: string;
  top_findings: FindingRisk[];
  assumptions: string[];
};

export type GhostSecret = {
  secret_type: string;
  masked_value: string;
  file_path: string;
  line: number;
  introduced: { short: string; author: string; date: string; subject: string };
  removed: { short: string; author: string; date: string; subject: string } | null;
  exposure_days: number;
};

export type HealingReport = {
  before_score: number;
  before_grade: string;
  after_score: number;
  after_grade: string;
  before_findings: number;
  after_findings: number;
  before_risk_kzt: number;
  after_risk_kzt: number;
  fixed_count: number;
  fixes: { file_path: string; fixers: string[]; diff: string; fixed_findings: string[]; verified: boolean }[];
  reverted_files: string[];
  manual_actions: { title: string; location: string; severity: string; action: string }[];
};

export const formatKzt = (n: number) => `${Math.round(n).toLocaleString('ru-RU').replace(/,/g, ' ')} ₸`;

const CARD_CLASS = 'bg-[var(--color-paper)] border border-[var(--color-line)] rounded-2xl p-5';
const LABEL_CLASS =
  'text-[11px] font-mono uppercase tracking-wider text-[var(--color-muted-soft)] mb-2.5 flex items-center gap-1.5';

// ---------- Financial Risk (ст. 79 КоАП РК) ----------

export function RiskCard({ risk }: { risk: FinancialRisk }) {
  const top = risk.top_findings[0]?.risk_kzt || 1;

  return (
    <div className={CARD_CLASS}>
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className={cn(LABEL_CLASS, 'mb-0')}>
          <Banknote className="w-3.5 h-3.5 text-[#e94a32]" aria-hidden="true" />
          <span>Финансовый риск (ст. 79 КоАП РК)</span>
        </div>
        <span className="font-mono text-[10px] px-2 py-0.5 rounded-full border border-[var(--color-line)] bg-[var(--color-panel)] text-[var(--color-muted-soft)]">
          КОАП РК
        </span>
      </div>

      <div
        className={cn(
          'text-2xl sm:text-3xl font-semibold font-mono tabular-nums mt-2',
          risk.total_kzt ? 'text-[#ff735d]' : 'text-[#3fbf7f]'
        )}
      >
        {risk.total_kzt ? `до ${formatKzt(risk.total_kzt)}` : '0 ₸'}
      </div>
      <p className="text-xs text-[var(--color-muted-soft)] mt-1 leading-relaxed">
        Штраф регулятора (ст. 79 КоАП РК):{' '}
        <span className="font-mono text-[var(--color-ink)]">{formatKzt(risk.regulatory_kzt)}</span>
        {risk.incident_kzt ? (
          <>
            {' '}· оценка инцидента (.aegis.yml):{' '}
            <span className="font-mono text-[var(--color-ink)]">{formatKzt(risk.incident_kzt)}</span>
          </>
        ) : null}
      </p>

      {risk.top_findings.length > 0 && (
        <ul className="mt-3.5 space-y-2">
          {risk.top_findings.slice(0, 4).map((r) => (
            <li key={r.finding_id} className="text-xs">
              <div className="flex justify-between gap-2">
                <span className="truncate text-[var(--color-body-text)]" title={r.title}>
                  {r.title}
                </span>
                <span className="font-mono text-[#ff735d] tabular-nums shrink-0">{formatKzt(r.risk_kzt)}</span>
              </div>
              <div className="h-1.5 rounded-full bg-[var(--color-panel)] mt-1 overflow-hidden">
                <div
                  className="h-full bg-[#e94a32]/80 rounded-full"
                  style={{ width: `${Math.max(4, (r.risk_kzt / top) * 100)}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}

      <details className="mt-4 pt-3 border-t border-[var(--color-line)] text-[11px] text-[var(--color-muted-soft)]">
        <summary className="cursor-pointer hover:text-[var(--color-ink)] transition-colors">
          База расчёта и допущения (МРП / .aegis.yml)
        </summary>
        <ul className="mt-1.5 list-disc pl-4 space-y-0.5 leading-relaxed">
          {risk.assumptions.map((a) => (
            <li key={a}>{a}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

// ---------- Git Time Machine ----------

export function GhostSecretsCard({ ghosts }: { ghosts: GhostSecret[] }) {
  if (!ghosts.length) return null;
  return (
    <div className={cn(CARD_CLASS, 'border-[#e94a32]/50')}>
      <div className={LABEL_CLASS}>
        <History className="w-3.5 h-3.5 text-[#e94a32]" aria-hidden="true" />
        <span>Машина времени Git (Ghost Secrets)</span>
      </div>
      <div className="space-y-4">
        {ghosts.map((g) => (
          <div key={`${g.introduced.short}-${g.masked_value}`} className="text-xs">
            <div className="text-[var(--color-ink)] font-medium flex flex-wrap items-center gap-2">
              <span>{g.secret_type}</span>
              <code className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-[#e94a32]/15 text-[#ff735d] border border-[#e94a32]/35">
                {g.masked_value}
              </code>
            </div>
            <ol className="relative border-l border-[var(--color-line-strong)] ml-1.5 mt-2.5 space-y-2.5 pl-4">
              <li>
                <span className="absolute -left-[5px] w-2.5 h-2.5 rounded-full bg-[#e94a32]" />
                <span className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                  {g.introduced.date.slice(0, 10)} · {g.introduced.short}
                </span>
                <div className="text-[var(--color-body-text)]">
                  Добавлен: «{g.introduced.subject}» — {g.introduced.author}
                </div>
              </li>
              {g.removed && (
                <li>
                  <span className="absolute -left-[5px] w-2.5 h-2.5 rounded-full bg-[#e8a33d]" />
                  <span className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                    {g.removed.date.slice(0, 10)} · {g.removed.short}
                  </span>
                  <div className="text-[var(--color-body-text)]">«Удалён» из HEAD: «{g.removed.subject}»</div>
                </li>
              )}
              <li>
                <span className="absolute -left-[5px] w-2.5 h-2.5 rounded-full bg-[#e94a32] animate-pulse" />
                <span className="font-mono text-[11px] text-[#ff735d]">сегодня</span>
                <div className="text-[var(--color-body-text)]">
                  Всё ещё восстанавливается через <code className="font-mono text-[11px]">git log -p</code>
                </div>
              </li>
            </ol>
            <div className="mt-3 px-2.5 py-1.5 rounded-lg bg-[#e94a32]/10 border border-[#e94a32]/30 font-mono text-[11px] text-[#ff735d]">
              Окно утечки: {g.exposure_days} дн. — удаление из файла не отзывает ключ
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------- Self-Healing With Proof ----------

function useCountUp(target: number, from: number, run: boolean, ms = 1200) {
  const [value, setValue] = useState(from);
  useEffect(() => {
    if (!run) return;
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ms);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(from + (target - from) * eased);
      if (t < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, from, run, ms]);
  return run ? value : from;
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="text-[11px] font-mono leading-relaxed overflow-x-auto bg-[#0a0a0a] border border-[#232323] rounded-lg p-3 mt-2">
      {diff.split('\n').map((line, i) => {
        const color =
          line.startsWith('+') && !line.startsWith('+++')
            ? 'text-[#3fbf7f] bg-[#3fbf7f]/10'
            : line.startsWith('-') && !line.startsWith('---')
            ? 'text-[#ff735d] bg-[#e94a32]/10'
            : line.startsWith('@@')
            ? 'text-sky-300'
            : 'text-[#8e8d88]';
        return (
          <div key={i} className={color}>
            {line || ' '}
          </div>
        );
      })}
    </pre>
  );
}

export function HealPanel({ report }: { report: HealingReport }) {
  const score = useCountUp(report.after_score, report.before_score, true);
  const risk = useCountUp(report.after_risk_kzt, report.before_risk_kzt, true, 1600);
  const scoreColor = score >= 75 ? 'text-[#3fbf7f]' : score >= 50 ? 'text-[#e8a33d]' : 'text-[#ff735d]';

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(CARD_CLASS, 'border-[#3fbf7f]/45')}
    >
      <div className={LABEL_CLASS}>
        <HeartPulse className="w-3.5 h-3.5 text-[#3fbf7f]" aria-hidden="true" />
        <span>Самоисцеление с доказательством — патч → ast.parse → пересканирование</span>
      </div>

      <div className="grid grid-cols-2 gap-2.5">
        <div className="rounded-xl bg-[var(--color-panel)] border border-[var(--color-line)] p-3 min-w-0">
          <div className="text-[10px] text-[var(--color-muted-soft)] font-mono">SECURITY SCORE</div>
          <div className={cn('text-xl sm:text-2xl font-semibold font-mono tabular-nums mt-0.5', scoreColor)}>
            {report.before_grade} → {Math.round(score)}
          </div>
          <div className="text-[11px] text-[var(--color-muted-soft)] font-mono tabular-nums">
            {report.before_score} → {report.after_score} (Grade {report.after_grade})
          </div>
        </div>
        <div className="rounded-xl bg-[var(--color-panel)] border border-[var(--color-line)] p-3 min-w-0">
          <div className="text-[10px] text-[var(--color-muted-soft)] font-mono">НАХОДКИ</div>
          <div className="text-xl sm:text-2xl font-semibold font-mono text-[var(--color-ink)] tabular-nums mt-0.5">
            {report.before_findings} → {report.after_findings}
          </div>
          <div className="text-[11px] text-[#3fbf7f] font-mono tabular-nums">
            подтверждённых фиксов: {report.fixed_count}
          </div>
        </div>
        <div className="col-span-2 rounded-xl bg-[var(--color-panel)] border border-[var(--color-line)] p-3 flex flex-wrap items-baseline justify-between gap-2 min-w-0">
          <div>
            <div className="text-[10px] text-[var(--color-muted-soft)] font-mono">РИСК КОАП + ИНЦИДЕНТ</div>
            <div className="text-lg sm:text-xl font-semibold font-mono text-[#3fbf7f] tabular-nums mt-0.5">
              {formatKzt(risk)}
            </div>
          </div>
          <div className="text-[11px] text-[var(--color-muted-soft)] font-mono tabular-nums">
            было {formatKzt(report.before_risk_kzt)}
          </div>
        </div>
      </div>

      <div className="mt-4 space-y-3">
        {report.fixes.map((fix) => (
          <details
            key={fix.file_path}
            className="rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] p-3"
            open={report.fixes.length <= 2}
          >
            <summary className="cursor-pointer text-xs flex flex-wrap items-center gap-2 text-[var(--color-ink)]">
              <CheckCircle2
                className={cn('w-3.5 h-3.5 shrink-0', fix.verified ? 'text-[#3fbf7f]' : 'text-[var(--color-muted-soft)]')}
                aria-hidden="true"
              />
              <code className="font-mono font-medium">{fix.file_path}</code>
              <span className="text-[var(--color-muted-soft)]">— {fix.fixers.join(' · ')}</span>
            </summary>
            <ul className="mt-2 ml-5 text-[11px] text-[#3fbf7f] list-none space-y-0.5">
              {fix.fixed_findings.map((t, i) => (
                <li key={i}>− {t}</li>
              ))}
            </ul>
            <DiffView diff={fix.diff} />
          </details>
        ))}
        {report.reverted_files.map((f) => (
          <div key={f} className="text-xs text-[#e8a33d] flex items-center gap-1.5 font-mono">
            <Undo2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>{f}: патч автоматически откатан — не снизил риск</span>
          </div>
        ))}
      </div>

      {report.manual_actions.length > 0 && (
        <div className="mt-4 border-t border-[var(--color-line)] pt-3.5">
          <div className={LABEL_CLASS}>
            <Hand className="w-3.5 h-3.5 text-[#e8a33d]" aria-hidden="true" />
            <span>Требует действия инженера (не лечится патчем кода)</span>
          </div>
          <div className="space-y-2">
            {report.manual_actions.map((m, i) => (
              <div key={i} className="text-xs text-[var(--color-body-text)]">
                <span className="font-mono text-[#ff735d]">[{m.severity}]</span> {m.title}{' '}
                <code className="font-mono text-[11px] text-[var(--color-muted-soft)]">{m.location}</code>
                <div className="text-[11px] text-[var(--color-muted-soft)] mt-0.5">→ {m.action}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
